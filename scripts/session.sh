#!/usr/bin/env bash

set -u

plugin_dir="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"

refuse() {
  echo "omassh: $1" >&2
  read -r -p "Press Enter to close. " _
  exit 64
}

(($# >= 2)) || refuse "usage: session.sh MODE ALIAS [--config PATH] [--command ID] [--no-forwards]"

mode="$1"
alias_name="$2"
shift 2

config=""
command_id=""
no_forwards=0
while (($# > 0)); do
  case "$1" in
    --config)
      (($# >= 2)) || refuse "--config needs a value"
      config="$2"
      shift 2
      ;;
    --command)
      (($# >= 2)) || refuse "--command needs a value"
      command_id="$2"
      shift 2
      ;;
    --no-forwards)
      no_forwards=1
      shift
      ;;
    *) refuse "unknown option" ;;
  esac
done

case "$mode" in
  ssh | sftp | tmux | run | copy-id) ;;
  *) refuse "unknown mode (expected ssh, sftp, tmux, run or copy-id)" ;;
esac

[[ $alias_name =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || refuse "refusing unsafe host name"

if [[ $mode == run ]]; then
  [[ $command_id =~ ^[0-9a-f]{16}$ ]] || refuse "refusing unsafe command id"
elif [[ -n $command_id ]]; then
  refuse "--command is only for the run mode"
fi

ssh_args=()
if [[ -n $config ]]; then
  if ! [[ $config =~ ^/[A-Za-z0-9._+@:,=/-]*$ ]] || [[ ! -f $config ]]; then
    refuse "refusing unsafe config path"
  fi
  ssh_args+=(-F "$config")
fi
if ((no_forwards)); then
  ssh_args+=(-o ClearAllForwardings=yes)
fi

printf '\033]0;%s %s\007' "$mode" "$alias_name"

case "$mode" in
  ssh | sftp)
    "$mode" ${ssh_args[@]+"${ssh_args[@]}"} -- "$alias_name"
    ;;
  tmux)
    ssh -t -o RemoteCommand=none ${ssh_args[@]+"${ssh_args[@]}"} -- "$alias_name" "tmux new-session -A -s omassh"
    ;;
  run)
    cmd="$("$plugin_dir/omassh" command-text --alias "$alias_name" -- "$command_id")" || refuse "that saved command is not available"
    printf '%s\n' "$cmd"
    ssh -t -o RemoteCommand=none ${ssh_args[@]+"${ssh_args[@]}"} -- "$alias_name" "$cmd"
    ;;
  copy-id)
    ssh-copy-id ${ssh_args[@]+"${ssh_args[@]}"} -- "$alias_name"
    ;;
esac
status=$?

if ((status != 0)) || [[ $mode == run || $mode == copy-id ]]; then
  printf '\n%s exited with status %d. Press Enter to close. ' "$mode" "$status"
  read -r _
fi
exit "$status"
