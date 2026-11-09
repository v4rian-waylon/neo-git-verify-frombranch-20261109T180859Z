#!/usr/bin/env python3
"""neo-git agent hook: PreToolUse(Bash) guard for Claude Code and Codex. Deterministic, no model call.

Reads the agent's hook JSON on stdin ({tool_input:{command}, cwd}); a deny is printed as
{hookSpecificOutput:{permissionDecision:"deny",permissionDecisionReason}} with the fix in the reason.
It decides on a real parse of the command and fails closed: input it cannot read, a command it
cannot parse or one too large to check is denied, never waved through.

Parsing. The command is tokenised as a shell would (quotes, escapes, operators). It is split into
simple commands at && || ; | & ( ) { } newlines and shell keywords. Command substitutions $(...),
`...`, <(...) and >(...) are parsed as commands of their own, and so are the scripts given to
bash/sh/zsh -c, eval, env -S, watch, a heredoc fed to a shell, and a script file run with bash,
sh or source. Wrappers (command, builtin, exec, nohup, time, nice, timeout, stdbuf, env, sudo,
doas, xargs) are peeled off and a path to a program (/usr/bin/git, \\git) counts as the program.
Paths are expanded (~, $HOME, $TMPDIR when set), made absolute against the tracked cwd, normalised
(a /tmp/../x path is x) and resolved through symlinks; a path still holding a variable or a command
substitution is unknown and an unknown target of a rule is denied.

Rules.
  1. No rm / unlink / shred / find -delete / find -exec rm / xargs rm outside temp roots:
     deletions go to the Trash. A deletion behind an env prefix or xargs is denied.
  2. No destructive git (reset --hard, checkout -f or -- <paths>, restore, switch -f, clean -f,
     force or delete push, branch -D/-M, rebase, filter-branch/filter-repo, stash drop/clear,
     reflog expire, gc --prune, update-ref -d, prune, worktree remove --force, tag -d) without a
     preflight backup that matches the repository now: a preflight-bak-* commit whose parent is the
     current HEAD (on origin when the repo has one), younger than PREFLIGHT_MAX_AGE_H, with its zip
     still on disk, and no changed path modified after it was taken.
     Exempt: throwaway repos whose worktree AND git common dir live under a temp root; a force push
     from one is exempt only when every remote is itself under a temp root.
     Linked worktrees accept the main repo's preflight; a reset --hard / checkout -f / clean -f
     then still needs the worktree's own preflight when the worktree has changes it would destroy.
     `<installed git-preflight.sh> <repo> ... && <destructive git on that repo>` counts as
     preflighted, only through an unbroken && chain and only when the command is the installed
     preflight script itself.
  3. No push to main (a main destination, --all or --mirror, or a bare push with main checked
     out), no bare --force or +refspec push, no remote repo deletion, no filter-branch -- --all,
     no git -c alias.<name>=!<shell>.
  4. No printing of credential files into the transcript.
  5. Protocol staging and trailer rules: no git add -A / . / :/ / -u, no commit -a, no staging of
     secrets or build output, no Co-Authored-By: Claude trailer on a commit.
Config: NEO_GIT_BAKS_DIR (bak zips, default $HOME/.neo-git/baks; BAKS_DIR is a legacy alias),
PREFLIGHT_MAX_AGE_H (12), GUARD_TMP_ROOTS (colon list that can only narrow the temp exemption).
"""
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PF = os.path.join(HERE, "git-preflight.sh")
MAX_CMD = 100000
MAX_DEPTH = 8
MAXH = int(os.environ.get("PREFLIGHT_MAX_AGE_H", "12") or "12")
BAKS = os.environ.get("NEO_GIT_BAKS_DIR") or os.environ.get("HOW_GIT_BAKS_DIR") or os.environ.get("BAKS_DIR") or os.path.join(os.path.expanduser("~"), ".neo-git", "baks")
HOME = os.path.expanduser("~")
TMPD = (os.environ.get("TMPDIR") or "").rstrip("/")


class Deny(Exception):
    pass


class Unparseable(Exception):
    pass


def deny(reason):
    raise Deny(reason)


def emit_deny(reason):
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                             "permissionDecision": "deny",
                                             "permissionDecisionReason": reason}}))


# --------------------------------------------------------------------------- tokeniser
OPS = ["&&", "||", ";;", "|&", "&>>", "&>", ">>", "<<<", "<<-", "<<", ">&", "<&", ">|", "<>",
       ";", "|", "&", "(", ")", "<", ">", "\n"]
SEPARATORS = {"&&", "||", ";;", ";", "|", "|&", "&", "(", ")", "\n"}
REDIRS = {">", ">>", ">|", "&>", "&>>", "<", "<>", ">&", "<&", "<<<"}
KEYWORDS = {"if", "then", "elif", "else", "fi", "do", "done", "while", "until", "{", "}", "!",
            "time", "coproc"}


class Word:
    """One shell word: its text with quotes removed, and whether it holds an expansion we
    did not resolve (a variable or a command substitution)."""
    __slots__ = ("text", "dynamic", "raw")

    def __init__(self, text, dynamic, raw):
        self.text, self.dynamic, self.raw = text, dynamic, raw


def _balanced(s, i, open_ch, close_ch):
    """Index just past the close_ch matching s[i] == open_ch, honouring quotes and nesting."""
    depth, j, n = 0, i, len(s)
    while j < n:
        c = s[j]
        if c == "\\":
            j += 2
            continue
        if c == "'":
            k = s.find("'", j + 1)
            if k < 0:
                raise Unparseable("unterminated single quote")
            j = k + 1
            continue
        if c == '"':
            j = _dq_end(s, j)
            continue
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    raise Unparseable("unbalanced %s%s" % (open_ch, close_ch))


def _dq_end(s, i):
    j, n = i + 1, len(s)
    while j < n:
        c = s[j]
        if c == "\\":
            j += 2
            continue
        if c == '"':
            return j + 1
        if c == "$" and j + 1 < n and s[j + 1] == "(":
            j = _balanced(s, j + 1, "(", ")")
            continue
        if c == "`":
            k = s.find("`", j + 1)
            if k < 0:
                raise Unparseable("unterminated backquote")
            j = k + 1
            continue
        j += 1
    raise Unparseable("unterminated double quote")


def tokenize(s, subs):
    """Split shell text into Word and operator tokens. Command substitutions are appended to
    `subs` (their inner text) and leave the word dynamic."""
    toks, i, n = [], 0, len(s)
    while i < n:
        c = s[i]
        if c in " \t":
            i += 1
            continue
        if c == "\\" and i + 1 < n and s[i + 1] == "\n":
            i += 2
            continue
        if c == "#" and (not toks or isinstance(toks[-1], str)):
            k = s.find("\n", i)
            i = n if k < 0 else k
            continue
        op = next((o for o in OPS if s.startswith(o, i)), None)
        if op and not (op in ("<", ">") and i + 1 < n and s[i + 1] == "(" ):
            toks.append(op)
            i += len(op)
            continue
        # a word
        text, raw_start, dynamic = [], i, False
        while i < n:
            c = s[i]
            if c in " \t\n" or (any(s.startswith(o, i) for o in OPS) and not (c in "<>" and i + 1 < n and s[i + 1] == "(")):
                break
            if c == "\\":
                if i + 1 < n:
                    text.append(s[i + 1])
                i += 2
                continue
            if c == "'":
                k = s.find("'", i + 1)
                if k < 0:
                    raise Unparseable("unterminated single quote")
                text.append(s[i + 1:k])
                i = k + 1
                continue
            if c == "$" and i + 1 < n and s[i + 1] == "'":
                k = s.find("'", i + 2)
                if k < 0:
                    raise Unparseable("unterminated $'' quote")
                text.append(s[i + 2:k])
                i = k + 1
                continue
            if c == '"':
                k = _dq_end(s, i)
                inner = s[i + 1:k - 1]
                sub_text, dyn = _expand_dq(inner, subs)
                text.append(sub_text)
                dynamic = dynamic or dyn
                i = k
                continue
            if c == "$" and i + 1 < n and s[i + 1] == "(":
                k = _balanced(s, i + 1, "(", ")")
                inner = s[i + 2:k - 1]
                if inner.startswith("("):  # $(( arithmetic ))
                    text.append("0")
                else:
                    subs.append(inner)
                    text.append("$(...)")
                    dynamic = True
                i = k
                continue
            if c in "<>" and i + 1 < n and s[i + 1] == "(":
                k = _balanced(s, i + 1, "(", ")")
                subs.append(s[i + 2:k - 1])
                text.append("/dev/fd/63")
                dynamic = True
                i = k
                continue
            if c == "`":
                k = s.find("`", i + 1)
                if k < 0:
                    raise Unparseable("unterminated backquote")
                subs.append(s[i + 1:k])
                text.append("$(...)")
                dynamic = True
                i = k + 1
                continue
            if c == "$":
                m = re.match(r"\$(\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*|[0-9#?$!@*-])", s[i:])
                if m:
                    text.append(m.group(0))
                    i += len(m.group(0))
                    continue
            text.append(c)
            i += 1
        toks.append(Word("".join(text), dynamic, s[raw_start:i]))
    return toks


def _expand_dq(inner, subs):
    """Text of a double-quoted string with substitutions recorded; variables are kept as
    written ($HOME, ${TMPDIR}) for the path expander."""
    out, j, n, dyn = [], 0, len(inner), False
    while j < n:
        c = inner[j]
        if c == "\\" and j + 1 < n and inner[j + 1] in '$`"\\\n':
            out.append(inner[j + 1])
            j += 2
            continue
        if c == "$" and j + 1 < n and inner[j + 1] == "(":
            k = _balanced(inner, j + 1, "(", ")")
            body = inner[j + 2:k - 1]
            if not body.startswith("("):
                subs.append(body)
                out.append("$(...)")
                dyn = True
            else:
                out.append("0")
            j = k
            continue
        if c == "`":
            k = inner.find("`", j + 1)
            subs.append(inner[j + 1:k])
            out.append("$(...)")
            dyn = True
            j = k + 1
            continue
        out.append(c)
        j += 1
    return "".join(out), dyn


# --------------------------------------------------------------------------- heredocs
HEREDOC_RE = re.compile(r"<<(-?)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")
SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "mksh", "fish"}


def split_heredocs(c):
    """Return (command text without heredoc bodies, [(line_text, body)])."""
    lines = c.split("\n")
    out, docs, i = [], [], 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        i += 1
        for m in HEREDOC_RE.finditer(line):
            tag, strip = m.group(3), m.group(1) == "-"
            body = []
            while i < len(lines) and (lines[i].lstrip("\t") if strip else lines[i]).strip() != tag:
                body.append(lines[i])
                i += 1
            i += 1
            docs.append((line, "\n".join(body)))
    return "\n".join(out), docs


# --------------------------------------------------------------------------- paths
TEMP_DEFAULTS = ["/tmp", "/private/tmp", "/var/folders", "/private/var/folders"]


def _real(p):
    """realpath of the deepest existing ancestor, with the rest appended (normalised)."""
    p = os.path.normpath(p)
    head, tail = p, []
    while head not in ("/", "") and not os.path.exists(head):
        head, t = os.path.split(head)
        tail.insert(0, t)
    base = os.path.realpath(head) if head else "/"
    return os.path.normpath(os.path.join(base, *tail)) if tail else base


def _temp_roots():
    roots = set()
    for r in TEMP_DEFAULTS + ([TMPD] if TMPD else []):
        roots.add(os.path.normpath(r))
        roots.add(_real(r))
    narrow = [x for x in (os.environ.get("GUARD_TMP_ROOTS") or "").split(":") if x]
    if narrow:
        kept = set()
        for r in narrow:
            rr = _real(r)
            if any(_under(rr, t) for t in roots):
                kept.add(rr)
        return roots, kept
    return roots, None


def _under(p, root):
    return p != root and (p + "/").startswith(root.rstrip("/") + "/")


def is_tmp(p, narrowed=True):
    roots, narrow = TEMP_ROOTS
    if not narrowed:
        narrow = None
    rp = _real(p)
    if not any(_under(rp, r) or _under(p, r) for r in roots):
        return False
    if narrow is None:
        return True
    return any(_under(rp, r) for r in narrow)


def expand(word, cwd, env):
    """Absolute normalised path for a word, or None when it holds anything unresolved."""
    if word.dynamic:
        return None
    t = word.text
    home = env.get("HOME", HOME)
    t = t.replace("${HOME}", home).replace("$HOME", home)
    tmp = env.get("TMPDIR", TMPD) if "TMPDIR" in env else TMPD
    tmp = (tmp or "").rstrip("/")
    if tmp:
        t = t.replace("${TMPDIR}", tmp).replace("$TMPDIR", tmp)
    if t.startswith("~/") or t == "~":
        t = home + t[1:]
    if "$" in t or t.startswith("~"):
        return None
    if not t.startswith("/"):
        if cwd is None:
            return None
        t = os.path.join(cwd, t)
    return os.path.normpath(t)


# --------------------------------------------------------------------------- git helpers
def git(*args, cwd=None):
    try:
        r = subprocess.run(["git"] + list(args), cwd=cwd, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout.strip() if r.returncode == 0 else None


# --------------------------------------------------------------------------- rules
SECRET_RE = re.compile(r"(\.gcm/store|\.credentials\.json|(^|/)\.auth(/|$)|(^|/)keys/|\.p8$|\.p12$|\.pem$|\.pfx$|\.key$|"
                       r"(^|/)\.env(\.(?!example$|sample$|template$|dist$)[^/]*)?$|(^|/)\.netrc$|(^|/)\.git-credentials$|(^|/)\.npmrc$|(^|/)\.pypirc$|"
                       r"(^|/)id_(rsa|ed25519|ecdsa|dsa)$|(^|/)\.aws/credentials$|(^|/)\.docker/config\.json$)")
READERS = {"cat", "less", "more", "head", "tail", "bat", "strings", "base64", "xxd", "od", "hexdump", "grep", "rg",
           "awk", "sed", "cut", "jq", "python", "python3", "node", "ruby", "perl", "open", "pbcopy", "curl", "tac",
           "nl", "tee", "diff", "cmp", "sort", "uniq", "zcat", "gzip"}
BANNED_STAGE_RE = re.compile(r"(\.DS_Store$|(^|/)\.auth(/|$)|(^|/)keys(/|$)|\.p8$|\.p12$|\.cer$|\.pem$|\.provisionprofile$|"
                             r"\.mobileprovision$|(^|/)build(-[^/]+)?(/|$)|(^|/)node_modules(/|$)|(^|/)\.env$|\.zip$|\.bak$)")
WRAPPERS_NOARG = {"command", "builtin", "exec", "nohup", "time", "caffeinate", "unbuffer", "noglob"}


class Ctx:
    """State carried across the simple commands of one command line."""

    def __init__(self, cwd, raw):
        self.cwd = cwd
        self.raw = raw
        self.pf_roots = set()      # repo roots preflighted earlier through an unbroken && chain
        self.has_commit = False


def parse_script(text, ctx, depth=0, inherited_chain=False):
    if depth > MAX_DEPTH:
        deny("Command too deeply nested to check (neo-git guard fails closed); split it into plain commands.")
    body, docs = split_heredocs(text)
    subs = []
    toks = tokenize(body, subs)
    for inner in subs:
        parse_script(inner, Ctx(ctx.cwd, ctx.raw), depth + 1)
    # heredocs fed to a shell are commands too
    for line, doc in docs:
        lt = tokenize(line.split("<<")[0], [])
        words = [t.text for t in lt if isinstance(t, Word)]
        if words and any(os.path.basename(w) in SHELLS for w in words):
            parse_script(doc, Ctx(ctx.cwd, ctx.raw), depth + 1)
    seg, sep = [], "^"
    for t in toks + ["\n"]:
        if isinstance(t, str) and t in SEPARATORS:
            if seg:
                run_segment(seg, sep, ctx, depth)
            seg = []
            sep = "&&" if t == "&&" else ("|" if t in ("|", "|&") else ";")
            continue
        seg.append(t)


def split_redirs(seg):
    words, redirs, i = [], [], 0
    while i < len(seg):
        t = seg[i]
        if isinstance(t, str):
            if t in REDIRS or t in ("<<", "<<-"):
                target = seg[i + 1] if i + 1 < len(seg) and isinstance(seg[i + 1], Word) else None
                redirs.append((t, target))
                i += 2
                continue
            i += 1
            continue
        # fd-number redirections: the number is glued to the operator in shell (2>&1)
        if re.fullmatch(r"[0-9]+", t.raw) and i + 1 < len(seg) and isinstance(seg[i + 1], str) and seg[i + 1] in REDIRS:
            i += 1
            continue
        words.append(t)
        i += 1
    return words, redirs


def run_segment(seg, sep, ctx, depth):
    if sep != "&&":
        ctx.pf_roots = set()
    words, redirs = split_redirs(seg)
    # drop shell keywords that open a compound command
    while words and words[0].text in KEYWORDS and not words[0].dynamic:
        words = words[1:]
    if not words:
        return
    if words[0].text in ("for", "select", "case", "function") or re.fullmatch(r"[^()]+\)", words[0].text):
        return
    env, envprefix = {}, False
    while words and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", words[0].text, re.S):
        k, v = words[0].text.split("=", 1)
        env[k] = v
        envprefix = True
        words = words[1:]
    if not words:
        return
    check_command(words, redirs, env, envprefix, ctx, depth, xargs=False)


def peel(words, env):
    """Strip wrappers; returns (words, env, xargs, script_texts)."""
    xargs = False
    while words:
        name = os.path.basename(words[0].text)
        if name in WRAPPERS_NOARG:
            words = words[1:]
            while words and words[0].text.startswith("-") and words[0].text != "-":
                words = words[1:]
            continue
        if name == "nice":
            words = words[1:]
            if words and words[0].text == "-n":
                words = words[2:]
            elif words and re.fullmatch(r"-[0-9]+", words[0].text):
                words = words[1:]
            continue
        if name == "timeout":
            words = words[1:]
            while words and words[0].text.startswith("-"):
                words = words[2:] if words[0].text in ("-s", "-k", "--signal", "--kill-after") else words[1:]
            words = words[1:]  # duration
            continue
        if name == "stdbuf":
            words = words[1:]
            while words and words[0].text.startswith("-"):
                words = words[1:]
            continue
        if name in ("sudo", "doas"):
            words = words[1:]
            while words and words[0].text.startswith("-"):
                words = words[2:] if words[0].text in ("-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U") else words[1:]
            continue
        if name == "env":
            words = words[1:]
            while words:
                t = words[0].text
                if t in ("-u", "--unset", "-C", "--chdir"):
                    words = words[2:]
                elif t in ("-S", "--split-string") and len(words) > 1:
                    return words[2:], env, xargs, [words[1].text + " " + " ".join(w.raw for w in words[2:])]
                elif t.startswith("-"):
                    words = words[1:]
                elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", t, re.S):
                    k, v = t.split("=", 1)
                    env[k] = v
                    words = words[1:]
                else:
                    break
            continue
        if name == "xargs":
            xargs = True
            words = words[1:]
            while words and words[0].text.startswith("-"):
                t = words[0].text
                words = words[2:] if t in ("-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a", "--max-args", "--max-procs",
                                           "--delimiter", "--arg-file", "--replace") else words[1:]
            continue
        break
    return words, env, xargs, []


def check_command(words, redirs, env, envprefix, ctx, depth, xargs):
    words, env, wx, scripts = peel(words, env)
    xargs = xargs or wx
    for sc in scripts:
        parse_script(sc, Ctx(ctx.cwd, ctx.raw), depth + 1)
    if not words:
        return
    first = words[0]
    name = os.path.basename(first.text)
    if first.dynamic or "$" in name:
        deny("Command name is computed at run time (%s); the neo-git guard cannot check it. Run the command directly." % first.raw)
    args = words[1:]

    # interpreters given a script
    if name in SHELLS or name in ("eval", "source", ".", "watch"):
        script = None
        if name == "eval" or name == "watch":
            rest = [w for w in args if not (name == "watch" and w.text.startswith("-"))]
            script = " ".join(w.text for w in rest)
        else:
            i = 0
            while i < len(args):
                t = args[i].text
                if re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", t) and i + 1 < len(args):
                    script = args[i + 1].text
                    break
                if t.startswith("-"):
                    i += 1
                    continue
                # a script file is the user's or the framework's own tool (bin/ship pushes main by
                # design); only inline scripts are commands typed here
                break
        if script:
            parse_script(script, Ctx(ctx.cwd, ctx.raw), depth + 1)
        return

    # cd tracking
    if name in ("cd", "pushd"):
        if args and args[0].text not in ("-",):
            p = expand(args[0], ctx.cwd, env)
            ctx.cwd = p
        elif not args:
            ctx.cwd = HOME
        return

    # neo-git new-repo bootstrap: the one sanctioned main seeding, with its own flags only
    if re.search(r"(^|/)\.io\.v4rian\.neo-git/bin/bootstrap-offgrid$", first.text):
        rest = [w.text for w in args]
        ok, i = True, 0
        while i < len(rest):
            if rest[i] in ("--dry-run", "-h", "--help"):
                i += 1
            elif rest[i] == "--remote" and i + 1 < len(rest) and re.fullmatch(r"[A-Za-z0-9._-]+", rest[i + 1]):
                i += 2
            else:
                ok = False
                break
        if ok:
            return

    # chained preflight: the installed git-preflight.sh itself, never a word that merely names it
    if name == "git-preflight.sh":
        p = expand(first, ctx.cwd, env) if "/" in first.text else None
        if p and _same_file(p, PF) and args:
            r = expand(args[0], ctx.cwd, env)
            root = git("rev-parse", "--show-toplevel", cwd=r) if r and os.path.isdir(r) else None
            if root:
                ctx.pf_roots.add(_real(root))
        return

    # rule 4: credential echo
    if name in READERS:
        to_file = any(op in (">", ">>", ">|", "&>", "&>>") and tgt is not None and not tgt.text.startswith("&")
                      for op, tgt in redirs)
        for w in args:
            if SECRET_RE.search(w.text) and not to_file:
                deny("Credential echo blocked: '%s' on a secret path would print the secret into the transcript. "
                     "Read it into a shell variable or let the consuming tool read the file itself. Offending: %s"
                     % (name, " ".join(x.raw for x in words)))

    # rule 6: shell writes into a vendored framework copy
    check_bash_writes(name, args, redirs, ctx, env)

    # find: -delete and -exec
    if name == "find":
        texts = [w.text for w in args]
        if "-delete" in texts:
            check_deletion([w for w in args if not w.text.startswith("-") and w.text not in ("(", ")", "!")][:1] or args[:1],
                           ctx, env, envprefix, True, words)
        for i, t in enumerate(texts):
            if t in ("-exec", "-execdir", "-ok", "-okdir"):
                inner = []
                for w in args[i + 1:]:
                    if w.text in (";", "+"):
                        break
                    inner.append(w)
                if inner:
                    check_command(inner, [], dict(env), envprefix, ctx, depth, xargs=True)
        return

    # rule 1: deletions
    if name in ("rm", "unlink", "shred", "srm"):
        targets = [w for w in args if not (w.text.startswith("-") and len(w.text) > 1)]
        check_deletion(targets, ctx, env, envprefix, xargs, words)
        return

    # rule 3: remote repo deletion
    if name == "gh":
        t = [w.text for w in args]
        joined = " ".join(t)
        if t[:2] == ["repo", "delete"] or (t[:1] == ["api"] and re.search(r"(-X|--method)\s*=?\s*DELETE", joined, re.I)
                                           and re.search(r"(^|\s)/?repos/[^/\s]+/[^/\s]+/?(\s|$)", joined)):
            deny("Remote repo deletion blocked (neo-git data-loss prevention): only the repo owner deletes a repo, by name, "
                 "by hand. Offending: %s" % " ".join(w.raw for w in words))
        return

    if name == "git":
        check_git(args, env, envprefix, ctx, words)


def _same_file(a, b):
    try:
        if os.path.realpath(a) == os.path.realpath(b):
            return True
        with open(a, "rb") as fa, open(b, "rb") as fb:
            return fa.read() == fb.read()
    except OSError:
        return False


def check_deletion(targets, ctx, env, envprefix, xargs, words):
    raw = " ".join(w.raw for w in words)
    msg = ("Deletion blocked (neo-git data-loss prevention): move it to the Trash (macOS: '/usr/bin/trash <path>', "
           "Linux: 'gio trash <path>') so it stays recoverable. Only absolute paths under /tmp, /private/tmp or "
           "$TMPDIR may be rm'd, never through xargs, -exec or an env prefix. Offending: %s" % raw)
    if envprefix or xargs or not targets:
        deny(msg)
    for w in targets:
        p = expand(w, ctx.cwd, env)
        if p is None or not is_tmp(p, narrowed=False):
            deny(msg)


# --------------------------------------------------------------------------- git
GIT_GLOBAL_WITH_ARG = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--super-prefix",
                       "--config-env", "--list-cmds"}


def check_git(args, env, envprefix, ctx, words):
    raw = " ".join(w.raw for w in words)
    gdir = ctx.cwd
    git_dir = env.get("GIT_DIR")
    i = 0
    while i < len(args):
        t = args[i].text
        if not t.startswith("-") or t == "-":
            break
        key, val = t, None
        if "=" in t and t.split("=", 1)[0] in GIT_GLOBAL_WITH_ARG:
            key, val = t.split("=", 1)
            i += 1
        elif t in GIT_GLOBAL_WITH_ARG:
            val = args[i + 1].text if i + 1 < len(args) else None
            if i + 1 < len(args) and args[i + 1].dynamic:
                val = None
                gdir = None
            i += 2
        else:
            i += 1
        if key == "-C" and gdir is not None:
            if val is None:
                gdir = None
            else:
                p = expand(args[i - 1], gdir, env) if not val.startswith("/") else os.path.normpath(val)
                gdir = p
        elif key == "-c" and val and re.match(r"alias\.[^=]+=\s*!", val):
            deny("git -c alias.<name>=!<shell> blocked (neo-git guard): a shell alias hides the command from the guard. "
                 "Run the command directly. Offending: %s" % raw)
        elif key == "--git-dir":
            git_dir = val
        elif key == "--work-tree" and val:
            gdir = os.path.normpath(os.path.join(gdir or "/", val))
    rest = args[i:]
    if not rest:
        return
    sub = rest[0].text
    sargs = [w.text for w in rest[1:]]

    if sub == "commit":
        ctx.has_commit = True
        if re.search(r"co-authored-by:\s*claude", ctx.raw, re.I) or any(re.search(r"co-authored-by:\s*claude", a, re.I) for a in sargs):
            deny("Co-Authored-By: Claude trailer blocked (neo-git protocol, githooks/commit-msg): commit without the trailer.")
        for j, a in enumerate(sargs):
            if a in ("-F", "--file") and j + 1 < len(sargs) or a.startswith("--file="):
                fp = sargs[j + 1] if a in ("-F", "--file") else a.split("=", 1)[1]
                full = fp if fp.startswith("/") else os.path.join(gdir or "/", fp)
                try:
                    if re.search(r"co-authored-by:\s*claude", open(full, errors="replace").read(), re.I):
                        deny("Co-Authored-By: Claude trailer blocked (neo-git protocol, githooks/commit-msg): commit without the trailer.")
                except OSError:
                    pass
        if any(re.fullmatch(r"-[a-zA-Z]*a[a-zA-Z]*", a) and not a.startswith("--") for a in _opts(sargs)) or "--all" in _opts(sargs):
            deny("git commit -a blocked (neo-git protocol): stage files by name, then commit. Offending: %s" % raw)

    if sub in ("add", "stage"):
        opts, paths = _split_dashdash(sargs)
        dry = any(o == "--dry-run" or re.fullmatch(r"-[A-Za-z]*n[A-Za-z]*", o) for o in opts)
        if not dry:
            if any(o in ("-A", "--all", "-u", "--update", "--no-ignore-removal") or re.fullmatch(r"-[A-Za-z]*[Au][A-Za-z]*", o)
                   for o in opts) or any(p in (".", "./", ":/", ":", "*", ":(top)") for p in paths):
                deny("git add -A / git add . blocked (neo-git protocol): stage files by name. Offending: %s" % raw)
        if any(BANNED_STAGE_RE.search(p) for p in paths):
            deny("Staging a banned file blocked (neo-git protocol: .DS_Store, .auth/, keys/, certificates, build/, "
                 "node_modules/, .env, *.zip, *.bak). Offending: %s" % raw)

    if sub == "filter-branch" and "--all" in sargs:
        deny("git filter-branch -- --all blocked (neo-git protocol). Offending: %s" % raw)

    destructive = None
    if sub == "push":
        destructive = check_push(sargs, gdir, raw)
    elif sub == "reset" and "--hard" in sargs:
        destructive = "git reset --hard"
    elif sub == "checkout" and (any(a in ("-f", "--force") for a in sargs) or "--" in sargs or "." in sargs):
        destructive = "git checkout --force"
    elif sub == "restore" and not ("--staged" in sargs and "--worktree" not in sargs and "-W" not in sargs):
        destructive = "git restore"
    elif sub == "switch" and any(a in ("-f", "--force", "--discard-changes") for a in sargs):
        destructive = "git switch --discard-changes"
    elif sub == "clean" and any(re.fullmatch(r"-[a-zA-Z]*f[a-zA-Z]*", a) or a == "--force" for a in sargs):
        destructive = "git clean -f"
    elif sub == "branch" and (any(a in ("-D", "-M", "-C") for a in sargs) or
                              (any(a in ("-d", "--delete", "-m", "--move") for a in sargs) and any(a in ("-f", "--force") for a in sargs))):
        destructive = "git branch -D"
    elif sub in ("rebase", "filter-branch", "filter-repo"):
        destructive = "history rewrite (%s)" % sub
    elif sub == "stash" and sargs[:1] and sargs[0] in ("drop", "clear"):
        destructive = "git stash drop/clear"
    elif (sub == "reflog" and sargs[:1] == ["expire"]) or (sub == "gc" and any(a.startswith("--prune") for a in sargs)) \
            or (sub == "update-ref" and "-d" in sargs) or sub == "prune":
        destructive = "ref/reflog pruning"
    elif sub == "worktree" and sargs[:1] == ["remove"] and any(a in ("-f", "--force") for a in sargs):
        destructive = "git worktree remove --force"
    elif sub == "tag" and any(a in ("-d", "--delete") for a in sargs):
        destructive = "git tag -d"
    if not destructive:
        return
    require_preflight(destructive, gdir, git_dir, sargs, sub, ctx, raw)


def _opts(sargs):
    return _split_dashdash(sargs)[0]


def _split_dashdash(sargs):
    if "--" in sargs:
        k = sargs.index("--")
        return [a for a in sargs[:k] if a.startswith("-")], [a for a in sargs[:k] if not a.startswith("-")] + sargs[k + 1:]
    return [a for a in sargs if a.startswith("-")], [a for a in sargs if not a.startswith("-")]


def check_push(sargs, gdir, raw):
    opts, pos, j = [], [], 0
    while j < len(sargs):
        a = sargs[j]
        if a in ("-o", "--push-option", "--repo", "--receive-pack", "--exec"):
            opts.append(a)
            j += 2
            continue
        (opts if a.startswith("-") else pos).append(a)
        j += 1
    force = any(o in ("-f", "--force") for o in opts)
    lease = any(o.startswith("--force-with-lease") for o in opts)
    if force and not lease:
        deny("Bare --force blocked (neo-git protocol): use --force-with-lease after a preflight. Offending: %s" % raw)
    refspecs = pos[1:]
    if any(o in ("--all", "--mirror") for o in opts):
        deny("Push to main blocked: --all / --mirror would push main; push the named branch. Offending: %s" % raw)
    plus = False
    delete = any(o in ("-d", "--delete") for o in opts)
    for r in refspecs:
        if r.startswith("+"):
            plus = True
            r = r[1:]
        dst = r.split(":", 1)[1] if ":" in r else r
        if r.startswith(":"):
            delete = True
        if dst in ("main", "refs/heads/main"):
            deny("Push to main blocked: main advances only through the release close-up (dev to main via the repo's "
                 "own ship/claim tooling), never by a direct push. Offending: %s" % raw)
    if plus and not lease:
        deny("A +refspec is a bare force push (neo-git protocol): use --force-with-lease after a preflight. Offending: %s" % raw)
    if not refspecs and gdir:
        cur = git("symbolic-ref", "--short", "HEAD", cwd=gdir) if os.path.isdir(gdir) else None
        if cur == "main":
            deny("Push to main blocked: main is checked out in %s and a bare 'git push' would advance it. Switch to a "
                 "pool branch or use the release close-up tooling." % gdir)
    if lease or plus:
        return "force push"
    if delete:
        return "remote branch deletion"
    return None


def require_preflight(destructive, gdir, git_dir, sargs, sub, ctx, raw):
    if gdir is None or (git_dir and not os.path.isabs(git_dir) and gdir is None):
        deny("Destructive git blocked (neo-git preflight): %s on a repository given by a run-time value; the guard "
             "cannot check its preflight. Run it with a literal path (git -C <repo>). Offending: %s" % (destructive, raw))
    root = git("rev-parse", "--show-toplevel", cwd=gdir) if os.path.isdir(gdir) else None
    if not root:
        deny("Destructive git blocked (neo-git preflight): %s but %s is not inside a git repo, so the preflight cannot be "
             "checked. Run it from inside the repo (cd <repo> && ...) or with git -C <repo>. Offending: %s" % (destructive, gdir, raw))
    root_p = _real(root)
    common = git("rev-parse", "--path-format=absolute", "--git-common-dir", cwd=root)
    gitdir = git("rev-parse", "--path-format=absolute", "--git-dir", cwd=root)
    common_p = _real(common) if common else ""
    gitdir_p = _real(gitdir) if gitdir else ""
    linked = bool(common_p) and common_p != gitdir_p
    mainroot = common_p[:-5] if common_p.endswith("/.git") else common_p

    if is_tmp(root_p) and common_p and is_tmp(common_p):
        if destructive not in ("force push", "remote branch deletion"):
            return
        remote_ok = not any(re.search(r"://|^[^/\s]+@[^\s]+:", a) for a in sargs)
        cfg = git("config", "--get-regexp", r"^remote\..*\.(url|pushurl)$", cwd=root) or ""
        for line in cfg.splitlines():
            url = line.split(None, 1)[1] if " " in line else ""
            u = url[7:] if url.startswith("file://") else url
            if not u.startswith("/"):
                u = os.path.join(root_p, u)
            if not is_tmp(_real(u)):
                remote_ok = False
        if remote_ok:
            return

    def wt_dirty():
        if destructive in ("git reset --hard", "git checkout --force", "git restore", "git switch --discard-changes"):
            return git("status", "--porcelain", "--untracked-files=no", cwd=root) or ""
        if destructive == "git clean -f":
            ignored = any(re.fullmatch(r"-[a-zA-Z]*[xX][a-zA-Z]*", a) for a in sargs)
            st = git("status", "--porcelain", "--untracked-files=all", *(["--ignored"] if ignored else []), cwd=root) or ""
            return "\n".join(l for l in st.splitlines() if l.startswith("??") or l.startswith("!!"))
        return ""

    wt_deny = ("Destructive git blocked (neo-git preflight): %s in linked worktree %s, whose uncommitted changes the main "
               "repo's preflight does not cover. Run first: \"%s\" \"%s\" \"before %s\"  then retry the exact command."
               % (destructive, root, PF, root, destructive))
    if root_p in ctx.pf_roots:
        return
    if linked and mainroot in ctx.pf_roots:
        if not wt_dirty():
            return
        deny(wt_deny)

    ok, why = preflight_matches(root, root_p)
    if ok:
        return
    if linked:
        ok_main, _ = preflight_matches(mainroot, mainroot)
        if ok_main:
            if not wt_dirty():
                return
            deny(wt_deny)
    deny("Destructive git blocked (neo-git preflight): %s on %s: %s. Run first: \"%s\" \"%s\" \"before %s\"  then retry "
         "the exact command, or chain both in one command (\"%s\" \"%s\" \"...\" && <command>)."
         % (destructive, root, why, PF, root, destructive, PF, root))


def preflight_matches(root, root_p):
    """(True, "") when a preflight backup covers the repository as it is now."""
    has_origin = git("remote", "get-url", "origin", cwd=root) is not None
    pattern = "refs/remotes/origin/" if has_origin else "refs/heads/"
    where = "on origin" if has_origin else "locally (repo has no origin)"
    refs = git("for-each-ref", "--sort=-committerdate", "--format=%(committerdate:unix) %(refname)", pattern, cwd=root) or ""
    head = git("rev-parse", "--verify", "-q", "HEAD", cwd=root) or ""
    now, limit = time.time(), MAXH * 3600
    changed = None
    for line in refs.splitlines():
        ts, ref = line.split(" ", 1)
        if "/preflight-bak-" not in ref:
            continue
        ts = int(ts)
        if now - ts > limit:
            return False, "no preflight-bak-* ref %s within %dh" % (where, MAXH)
        parent = git("rev-parse", "--verify", "-q", ref + "^1", cwd=root) or ""
        if parent != head:
            continue
        body = git("log", "-1", "--format=%B", ref, cwd=root) or ""
        m = re.search(r"^Zip: (.+)$", body, re.M)
        zipf = m.group(1).strip() if m else ""
        name = os.path.basename(root)
        # the preflight is of this repository (a linked worktree's own, not its main repo's)
        if not os.path.basename(zipf).startswith(name + "-bak-"):
            continue
        if not os.path.isfile(zipf) or now - os.path.getmtime(zipf) > limit:
            return False, "no %s-bak-*.zip in %s within %dh" % (name, BAKS, MAXH)
        if changed is None:
            st = git("status", "--porcelain", "--untracked-files=all", "-z", cwd=root) or ""
            changed = [e[3:] for e in st.split("\0") if len(e) > 3]
        for path in changed:
            full = os.path.join(root, path)
            try:
                if os.path.getmtime(full) > ts + 1:
                    return False, "%s changed after the newest matching preflight" % path
            except OSError:
                continue
        return True, ""
    return False, "no preflight-bak-* ref %s for the current HEAD within %dh" % (where, MAXH)


VENDORED_MSG = ("Write blocked (neo-git protocol): vendored .io.v4rian.neo-git copies are never edited; change the "
                "canonical framework repo and run .io.v4rian.neo-git/bin/sync-framework <ref> here. Path: %s")


def vendored(path):
    """True when an absolute path lies inside a vendored .io.v4rian.neo-git copy: the real path (symlinks
    resolved, compared case-insensitively) is under a namespace dir whose repo does not commit the
    FRAMEWORK_REPO marker (an untracked marker someone just created does not count)."""
    rp = _real(path)
    parts = rp.split("/")
    low = [x.lower() for x in parts]
    if ".io.v4rian.neo-git" not in low:
        return False
    k = low.index(".io.v4rian.neo-git")
    root = "/".join(parts[:k]) or "/"
    marker = ".io.v4rian.neo-git/FRAMEWORK_REPO"
    if os.path.isfile(os.path.join(root, marker)) and git("ls-files", "--error-unmatch", marker, cwd=root) is not None:
        return False
    return True


WRITE_CMDS = {"tee", "touch", "truncate", "cp", "mv", "install", "ln", "rsync", "dd", "sed", "perl", "patch"}


def check_bash_writes(name, args, redirs, ctx, env):
    targets = [t for op, t in redirs if op in (">", ">>", ">|", "&>", "&>>", "<>") and t is not None]
    texts = [w.text for w in args]
    if name in ("tee", "touch", "truncate"):
        targets += [w for w in args if not w.text.startswith("-")]
    elif name in ("cp", "mv", "install", "ln", "rsync"):
        pos = [w for w in args if not w.text.startswith("-")]
        if "-t" in texts and texts.index("-t") + 1 < len(args):
            targets.append(args[texts.index("-t") + 1])
        elif pos:
            targets.append(pos[-1])
    elif name in ("sed", "perl") and any(t == "-i" or t.startswith("-i") or t.startswith("--in-place") or re.fullmatch(r"-[a-zA-Z]*i[a-zA-Z]*", t) for t in texts):
        targets += [w for w in args if not w.text.startswith("-")][1:]
    elif name == "dd":
        targets += [Word(w.text[3:], w.dynamic, w.raw) for w in args if w.text.startswith("of=")]
    for w in targets:
        p = expand(w, ctx.cwd, env)
        if p is not None and vendored(p):
            deny(VENDORED_MSG % p)


def main_write():
    """PreToolUse(Write|Edit|NotebookEdit) entry: deny a write into a vendored namespace copy."""
    try:
        inp = json.loads(sys.stdin.read())
        ti = inp.get("tool_input") or {}
        fp = ti.get("file_path") or ti.get("notebook_path")
        cwd = inp.get("cwd") or os.getcwd()
    except (ValueError, AttributeError):
        emit_deny("neo-git guard: the hook input is not valid JSON; the write was not checked, so it is refused.")
        return
    if not fp:
        return
    path = fp if fp.startswith("/") else os.path.join(cwd, fp)
    try:
        if vendored(os.path.normpath(path)):
            emit_deny(VENDORED_MSG % fp)
    except Exception as e:
        emit_deny("neo-git guard: internal error (%s: %s); the write was refused." % (type(e).__name__, e))


TEMP_ROOTS = None


def main():
    global TEMP_ROOTS
    data = sys.stdin.read()
    try:
        inp = json.loads(data)
        cmd = (inp.get("tool_input") or {}).get("command")
        cwd = inp.get("cwd") or os.getcwd()
    except (ValueError, AttributeError):
        emit_deny("neo-git guard: the hook input is not valid JSON; the command was not checked, so it is refused.")
        return
    if isinstance(cmd, list):
        cmd = " ".join(str(x) for x in cmd)
    if not cmd:
        return
    if len(cmd) > MAX_CMD:
        emit_deny("neo-git guard: the command is %d characters, more than the %d the guard checks; split it into "
                  "smaller commands." % (len(cmd), MAX_CMD))
        return
    TEMP_ROOTS = _temp_roots()
    ctx = Ctx(os.path.normpath(cwd), cmd)
    try:
        parse_script(cmd, ctx)
    except Deny as d:
        emit_deny(str(d))
    except Unparseable as u:
        emit_deny("neo-git guard: the command could not be parsed (%s), so it is refused; fix the quoting or split it." % u)
    except Exception as e:  # fail closed on any defect of the guard itself
        emit_deny("neo-git guard: internal error (%s: %s); the command was refused. Report it with the command." %
                  (type(e).__name__, e))


if __name__ == "__main__":
    if sys.argv[1:2] == ["--write"]:
        TEMP_ROOTS = _temp_roots()
        main_write()
    else:
        main()
