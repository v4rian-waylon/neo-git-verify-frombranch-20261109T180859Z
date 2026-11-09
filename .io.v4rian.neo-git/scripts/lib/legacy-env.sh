# shellcheck shell=bash
# neo-git was named how-git before v2026.0.185. Settings exported under the
# old HOW_GIT_* names keep working: each one fills its NEO_GIT_* twin when
# the twin is unset. Sourced by scripts/_lib.sh and scripts/lib/identity.sh.
for _ng_old in $(compgen -v HOW_GIT_ 2>/dev/null); do
  _ng_new="NEO_GIT_${_ng_old#HOW_GIT_}"
  if [ -z "${!_ng_new+x}" ]; then
    export "$_ng_new=${!_ng_old}"
  fi
done
unset _ng_old _ng_new
