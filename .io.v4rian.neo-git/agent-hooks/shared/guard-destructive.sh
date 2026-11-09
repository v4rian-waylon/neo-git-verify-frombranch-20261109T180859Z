#!/usr/bin/env bash
# neo-git agent hook: PreToolUse(Bash) guard for Claude Code and Codex. The rules and the parser
# live in guard_destructive.py next to this file (its docstring is the reference). This wrapper
# fails closed: without python3 or the module the command is refused, never waved through.
here=$(cd "$(dirname "$0")" && pwd)
if ! command -v python3 >/dev/null 2>&1 || [ ! -f "$here/guard_destructive.py" ]; then
  printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"neo-git guard: python3 or guard_destructive.py is missing, so the command was not checked and is refused; reinstall with bin/install-agent-hooks."}}'
  exit 0
fi
exec python3 "$here/guard_destructive.py"
