#!/bin/zsh
cd "$(dirname "$0")" || exit 1
if [[ -x /opt/anaconda3/envs/CodexCtl/bin/python ]]; then
  exec /opt/anaconda3/envs/CodexCtl/bin/python desktop.py
else
  exec python3 desktop.py
fi
