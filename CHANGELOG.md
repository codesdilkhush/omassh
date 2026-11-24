# Changelog

## 0.1.0

First release.

- Bar widget with a popup that lists the hosts in `~/.ssh/config`
  (including `Include`d files), searchable, with the host's user, hostname,
  port and jump host shown. Options are resolved the way ssh resolves them
  (wildcard `Host` blocks, negation, first value wins, `Include` inside blocks,
  the ProxyJump/ProxyCommand rule) and verified against the real `ssh -G`,
  including a seeded fuzz of random configs.
- Enter (or a click) opens the host in a terminal; `s` opens SFTP instead.
- Pin hosts to the top; recently used hosts come next.
- Optional reachability check (`r` or the refresh button, or `autoProbe`):
  a plain TCP connect to the SSH port. Hosts behind `ProxyJump` or
  `ProxyCommand` are never probed directly, wherever that is configured
  (own block, wildcard block, global, included file). If a `Match` block could
  change where a host connects, nothing is probed.
- `e` opens the config in your editor.
- Actions page per host (`a` or the right arrow): terminal, SFTP, tmux
  (attach to or create the remote session `omassh`), tunnel, copy, ssh-copy-id,
  VS Code Remote and saved commands. Rows for tools that are not installed
  are hidden.
- Tunnels: one background `ssh -N -f` per host carrying the host's
  `LocalForward`, `RemoteForward` and `DynamicForward` lines, run with
  `BatchMode`. A systemd user agent socket is picked up when the shell has no
  `SSH_AUTH_SOCK`. Tunnels are recorded with pid, start time and boot id and
  verified before they are listed or stopped. A normal connect to a host with a
  tunnel up (except SFTP) drops the config's forwards. `x` stops a tunnel; a
  header button stops all of them. At most 64 tunnels run at once. Tunnels run
  without askpass (`SSH_ASKPASS_REQUIRE=never`).
- Saved commands in `~/.config/omassh/commands.json`, optionally limited to
  hosts, run on the remote host in a terminal that stays open until you press
  Enter. A terminal argv carries only the command's id, and the panel gets an
  80-character preview. `omassh commands edit` (and the `c` key) creates the
  file when it is missing and opens it in the editor; a failure is shown in the
  panel.
- Host editor: add (`n`), modify (`m`), rename and delete (`d`) hosts from the
  panel. Hosts are stored in `~/.ssh/omassh.config` (`0600`), a canonical file
  the plugin owns; a hand edit makes it `foreign` and the panel leaves it
  alone. ssh reads it through one `Include ~/.ssh/omassh.config` line that the
  panel inserts above the first directive of `~/.ssh/config` after a preview,
  a confirmation and a timestamped backup in `~/.ssh` (a symlinked config is
  followed after ownership, mode, link-count and directory checks). The
  panel reports whether the Include is missing, active, late or scoped and
  saves only when it is active. Fields (name, address, user, port, jump hosts,
  key file, loopback or bare-port forwards) are validated by strict ASCII
  grammars; every save is checked with `ssh -G -F` on the generated file
  before it is written atomically with a rolling `omassh.config.bak`. Two
  panels are told apart by a per-host fingerprint and a lock. Hosts that
  another file also defines are read-only, and a name defined anywhere else is
  refused; while part of the config could not be read (a skipped `Include`, a
  cap) saving is refused altogether. A jump chain that leads back to the host is
  refused. Deleting stops the host's tunnel when only `omassh.config` defines
  the name and forgets its pin and recent entry once nothing defines it any
  more; renaming moves them and is refused while a tunnel is up. The Include
  line is added only when the host file is missing or canonical, keeping the
  owner, group and mode of `~/.ssh/config`. Off while `configPath` is set.
- Copy `ssh <alias>` or `user@host` to the clipboard (`wl-copy`).
- Pixel-art bar icon drawn on a canvas, with a badge and a tooltip count while
  tunnels are up.
- English, Spanish (neutral) and Japanese translations.
- `omassh` command line: `list` (version 3, with `origin`, `editable` and an
  `editor` block), `probe`, `connect` (`--sftp`, `--tmux`, `--copy-id`,
  `--run`), `copy`, `code`, `command-text`, `commands edit`,
  `tunnel start|stop|list`, `pin`, `unpin`, `host validate|save|delete` (the
  request is one JSON line on stdin) and `include status|apply`. Exit codes: 2
  usage, 3 unknown host, field errors or unusable saved command, 4 missing
  tool, 5 tunnel failure, 6 a host or Include change refused.
- `configPath` setting for a non-default config (shell-neutral characters only);
  ssh/sftp are then run with `-F` so the connection uses the same file the list
  was read from.
- Security: aliases are whitelisted and must exist in your config, terminals are
  started from argument lists only with every value restricted to shell-neutral
  characters, `--` precedes every host, the only writes to your SSH files are
  `omassh.config` and the single confirmed Include line in `~/.ssh/config`
  (with a backup), no passwords are stored, no recurring timers (only a 5 second watchdog while a save, delete or include command runs), no network traffic until
  you ask for a reachability check or a tunnel. `ssh -G` runs only with `-F`
  on the file the editor generates, never on your config. Host values travel on
  stdin, never on a command line, and are limited to ASCII grammars that cannot
  express another ssh option; `ProxyJump` hops are parsed structurally. Files
  are opened without following links, relative to a verified `~/.ssh`
  descriptor. Forward text never reaches a command line, tunnels are signalled
  only after verification through a pidfd, and the saved commands file must be
  yours and not writable by others.
