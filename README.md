<div align="center">
<pre>
█▀▀ █▀▀ █ █
▀▀█ ▀▀█ █▀█
▀▀▀ ▀▀▀ ▀ ▀
</pre>
<h1>OmaSSH</h1>
</div>

An [Omarchy](https://omarchy.org) bar plugin that turns your `~/.ssh/config`
into a host picker: click the terminal icon, type a few letters, press Enter,
and you are in a terminal connected to that host. Think of it as a small,
keyboard-first "saved hosts" list, built on plain OpenSSH, so everything keeps
working outside the plugin too.

## Features

- **Host list from your SSH config** - every `Host` alias, including files
  pulled in with `Include`. Each row shows `user@hostname:port` and any jump
  host, resolved the way ssh itself does it (wildcard blocks such as
  `Host *`, first value wins, `Include` inside blocks). The tests compare the
  result with the real `ssh -G`.
- **Search** - press `/`, or click the box; matches alias, hostname and user.
- **One key to connect** - Enter or a click opens the host in your default
  terminal; `s` opens SFTP instead. If the connection fails the window stays
  open so you can read the error.
- **Pin and recent** - pinned hosts first, then the ones you used last.
- **Reachability dots** (optional) - a plain TCP check of the SSH port.
  Cyan = reachable, red = not, grey = not checked. Hosts behind a jump host
  or proxy command are never probed directly.
- **Tunnels** - a host's `LocalForward`, `RemoteForward` and `DynamicForward`
  lines are listed on its actions page and started and stopped as one
  background tunnel. ssh reads the forwards from the config itself; the plugin
  never puts them on a command line.
- **Host editor** - add, edit, rename and delete hosts from the panel (`n`,
  `m`, `d`). They are stored in `~/.ssh/omassh.config`, a file the plugin owns,
  which ssh reads through one `Include` line the panel adds to `~/.ssh/config`
  after a preview and your confirmation. Every save is checked with the real
  `ssh -G` before it is written. See [Host editor](#host-editor).
- **Actions page** - `a` or the right arrow opens a page per host with
  everything below.
- **tmux** - attach to the remote tmux session `omassh`, creating it if it does
  not exist.
- **Saved commands** - named one-line commands kept in
  `~/.config/omassh/commands.json`, run on the remote host in a terminal that
  stays open until you press Enter. Optionally limited to certain hosts.
- **Copy** - `ssh <alias>` (with `-F <file>` when `configPath` is set) or
  `user@host` to the clipboard.
- **ssh-copy-id** - install your public key on the host from a terminal that
  stays open until you press Enter.
- **VS Code Remote** - open the host in a Remote - SSH window.
- **Bar icon** - a pixel-art `SSH` drawn on a canvas, with two accent-coloured
  squares as a badge while a tunnel is up and the count in the tooltip. Nothing
  watches the tunnels: the badge is refreshed when the panel opens or a tunnel
  action runs, so a tunnel that dies leaves it on until then.
- **Edit config** - `e` opens the SSH config in your editor.
- **`omassh` CLI** - the same operations from a shell.
- Follows your Omarchy theme and language: English, Spanish (neutral, used for every Spanish locale) and Japanese.

## Requirements

- Omarchy with shell-plugin support (4.x "Quattro")
- `openssh` (provides `ssh`, `sftp` and `ssh-copy-id`), `python3` (standard library only - no virtualenv, nothing to pip install)
- A Nerd Font (Omarchy ships one), only for the panel's small buttons and action icons; the bar icon is drawn, not a glyph
- `wl-clipboard` for the copy actions (hidden without `wl-copy`)
- `tmux` on the remote host for the tmux action
- `code` (VS Code) with its Remote - SSH extension, optional; the action is hidden without it
- Tunnels need a key without a passphrase or loaded in an agent, and a host key you already trust (see [Tunnels](#tunnels))

## Install

```bash
omarchy plugin add <git-url-or-local-path> --enable
```

For a local checkout: `omarchy plugin add /path/to/omassh --enable` (needs at
least one commit). The widget lands in the right section of the bar; move it
with `omarchy bar move paulorivera27.omassh --section left`.

Then add hosts in the panel (see [Host editor](#host-editor)) or the normal
way, in `~/.ssh/config`:

```
Host server
    HostName server.example.com
    User admin

Host prod-db
    HostName db.example.com
    User deploy
    ProxyJump bastion
```

## Using it

Host list:

| Key | Action |
| --- | --- |
| click the icon | open / close the popup |
| `/` | focus the search box (Esc clears it; Enter connects to the first match) |
| `j` / `k` or arrows | move |
| Enter, Space or click | open in a terminal |
| `a`, `l` or right arrow | actions page of the host |
| `s` | open SFTP |
| `t` | open in tmux |
| `f` | start / stop the tunnel |
| `y` | copy the ssh command (needs `wl-copy`) |
| `x` or Delete | stop the tunnel of the host |
| `p` | pin / unpin |
| `r` | check which hosts are reachable |
| `e` | edit the SSH config |
| `n` | new host (opens the Include setup first when ssh does not read `omassh.config` yet) |
| `m` | modify the selected host (only hosts stored in `omassh.config`) |
| `d` | delete the selected host from `omassh.config`, after a confirmation (the Delete key and `x` only stop its tunnel) |
| Tab / Shift+Tab | switch to the neighbouring bar panel |
| Esc | close |

The `+` button in the header does the same as `n`. A host stored in
`omassh.config` shows a small marker; its tooltip says so.

Actions page (the rows shown depend on the tools installed and on the host):

| Key | Action |
| --- | --- |
| `j` / `k` or arrows | move |
| Enter or Space | run the row under the cursor |
| `s`, `t`, `f`, `y` | SFTP, tmux, start / stop tunnel, copy ssh command |
| `u` | copy `user@host` (only when both parts are plain enough to paste into a shell) |
| `i` | `ssh-copy-id` |
| `v` | VS Code Remote (hidden when `configPath` is set) |
| `1`-`9` | run the first nine saved commands that apply to the host |
| `c` | edit the saved commands |
| `x` or Delete | stop the tunnel of the host |
| `p`, `r`, `e` | pin, check reachability, edit the SSH config |
| `m`, `d` | modify or delete the host (rows "Edit host" and "Delete host", shown for hosts that `omassh.config` defines) |
| `h` or left arrow, Esc | back to the host list |

The actions page also lists the host's port forwards (up to 32; the rest are
counted) and the saved commands that apply to it.

Edit page (new or existing host):

| Key | Action |
| --- | --- |
| Tab / Shift+Tab | next / previous field, wrapping; stays inside the form |
| Enter | save (not on the "Add forward" button) |
| Esc | cancel without saving |

Setup page (the Include line): Enter adds the line, Esc goes back.

Open it from a keybinding or script: `qs -p /usr/share/omarchy/shell ipc call paulorivera27.omassh toggle`.

### Settings

Add to the plugin's entry in `~/.config/omarchy/shell.json` (or use
`omarchy bar set paulorivera27.omassh <key> <value> --json`):

| Setting | Default | Meaning |
| --- | --- | --- |
| `autoProbe` | `false` | run the reachability check every time the popup opens |
| `configPath` | `""` | read a different SSH config: an absolute path made only of letters, digits and `. _ + @ : , = / -` (no spaces or shell characters). Connections then run `ssh -F <that file>`, so the list and the connection always agree. The host editor is off while it is set |

### Tunnels

A tunnel is one background `ssh -N -f` per host that carries every forward
the host has in your config (`LocalForward`, `RemoteForward`, `DynamicForward`,
from any applying block). ssh reads the forwards itself; the plugin never puts
forward text on a command line. Start and stop it with `f`, stop it with `x`,
or stop all of them from the stop button in the panel header.

- It runs with `BatchMode=yes` and `SSH_ASKPASS_REQUIRE=never`, without a
  terminal, so ssh has no way to ask for a password, passphrase or host-key
  confirmation: it fails instead. The key must be in an agent or have no
  passphrase, and the host key must already be in `known_hosts`: connect once
  in a terminal first.
- A jump host (`ProxyJump`) is reached by a second ssh that your ssh starts
  with only the options from your config: it does not inherit `BatchMode`,
  `ControlMaster=no` or `ControlPath=none`. It has no terminal and no askpass
  either, so it cannot prompt, but a `ControlMaster auto` with `ControlPersist`
  in your config can leave a master connection to the jump host behind after
  `tunnel stop`. Close it with `ssh -O exit <jump host>`.
- The shell that runs the bar often has no `SSH_AUTH_SOCK`. When it is unset
  and `$XDG_RUNTIME_DIR/ssh-agent.socket` is a socket you own, the tunnel uses
  that one (the systemd user agent). The explicit alternative is
  `IdentityAgent` in the host's config block, which does not depend on the
  environment.
- It also runs with `ExitOnForwardFailure=yes`, `ControlMaster=no`,
  `ControlPath=none`, `RemoteCommand=none` and `PermitLocalCommand=no`, and
  gives up after 20 seconds. At most 64 tunnels run at once; a new one is
  refused with the reason `limit` until you stop another.
- Tunnels survive a restart of the shell and end at logout. Each one is
  recorded with its pid, process start time and the boot id, and is checked
  against all three, its owner and its exact command line before it is listed
  or stopped; a recycled pid is never signalled.
- A normal connect (terminal, tmux, saved command, `ssh-copy-id`) to a host
  whose tunnel is up drops the config's forwards for that session
  (`ClearAllForwardings=yes`), so the ports are not bound twice. SFTP is left
  alone: it clears forwards itself.

### Saved commands

`~/.config/omassh/commands.json` (under `$XDG_CONFIG_HOME` when it is an
absolute path). `omassh commands edit`, the `c` key and the last row of the
actions page create it when it is missing and open it in your editor.

```json
{
  "commands": [
    { "name": "Disk usage", "command": "df -h" },
    { "name": "Web logs", "command": "journalctl -u nginx -n 100", "hosts": ["server", "web"] }
  ]
}
```

| Field | Rule |
| --- | --- |
| `name` | required, 60 characters at most |
| `command` | required, one line of 1000 characters at most, run by the remote shell |
| `hosts` | optional list of aliases (200 at most); without it the command is offered for every host |

- An entry with a missing or non-string field, text containing control or
  line-separator characters, an invalid alias in `hosts` or a duplicate is
  skipped; the panel says how many were skipped. More than 50 entries, a
  file over 64 KiB or invalid JSON ignores the whole file and the panel says
  why.
- The file must be a regular file you own that is not writable by group or
  others, or a symlink to one (dotfile managers); the target is what is
  checked. Otherwise it is ignored. The permissions of the directory that holds
  it are not checked: a file someone else puts there is not yours, so it is
  refused.
- The terminal stays open after the command, whatever its status, until you
  press Enter.
- The command runs on the remote host as `ssh -t -- <alias> <command>`, after
  the terminal prints it. It is never run locally.
- An entry's id is a hash of its name and text, so editing an entry invalidates
  a stale reference to the old one.

### Host editor

The panel edits one file, `~/.ssh/omassh.config` (mode `0600`). Hosts you write
by hand in `~/.ssh/config` or any other file are never edited; they stay yours.
The editor is off while `configPath` is set, because the plugin then reads a
file it does not manage.

**Setup: one Include line.** ssh reads `omassh.config` only when
`~/.ssh/config` has `Include ~/.ssh/omassh.config`. The first `n` shows a
preview of that single line in place, with a few lines of context. Enter adds
it. Nothing is written without that confirmation.

- The line goes above the first directive of the file, after any leading
  comments and blank lines, in the line ending that directive uses. A missing
  file is created (`0600`, and `~/.ssh` as `0700` when absent) holding only that
  line.
- It has to be first. An `Include` inside a `Host` or `Match` block is scoped to
  that block, and a global option above it (`User deploy`) beats the value of
  every managed host, because for most options ssh uses the first value it
  finds.
- Before the change, the old file is copied to
  `~/.ssh/config.omassh-<UTC timestamp>-<4 hex>.bak` (`0600`, created
  exclusively, never overwritten). The change is a rename of a new file, so
  close `~/.ssh/config` in your editor first.
- The preview carries a fingerprint of the path and the exact bytes. If the file
  changed since you looked, the apply is refused and the panel shows the new
  preview.
- If the line is already effective, nothing is touched.
- The new file keeps the owner, the group and the mode of the old one and the
  mode is never widened. When the file belongs to a group you are not in, so
  the group cannot be kept, the apply is refused (`group`) and the page shows
  the line to add by hand.
- It is refused while `omassh.config` exists but is not a file the plugin wrote
  (`managed-foreign`) or is not safe to read (`managed-unsafe`): once the line
  is in, ssh reads that file for every host, and one unknown option in it makes
  ssh fail for all of them. Only a missing or canonical host file is included.
  The check runs again at apply time and just before the rename, so a hand
  edit made after the preview is caught. The page then explains the problem
  and does not offer the manual line.

The panel reads the state from the real parse of your config (the same parser
that lists the hosts), not by matching text, so `Include omassh.config`, an
absolute path, a glob or an include nested in another included file all count.

| Include | Meaning | What the panel does |
| --- | --- | --- |
| `missing` | ssh does not read the file | banner "Hosts you add are saved in omassh.config..." with the number of hosts waiting; `n` opens the setup |
| `active` | read at the top level before any directive | no banner; hosts can be added and edited |
| `late` | read at the top level, but a directive comes first (a global option, or an earlier `Include`) | banner with the file and line; saves are refused; `n` opens the setup, which adds a fresh line at the top. The old line is harmless (ssh reads the file twice) and you can remove it |
| `scoped` | read only inside a `Host` or `Match` block | banner with the file and line; saves are refused; `n` opens the setup |

If `~/.ssh/config` is a symlink (dotfile managers), the preview shows
`~/.ssh/config -> <target>`, the target is changed, and the link stays. The
target must be a regular file you own, not writable by group or others, not
hard-linked, at most 1 MiB, without a byte order mark, in a directory you own
that others cannot write to. The backup always goes into `~/.ssh`, not into the
dotfiles repository. When any of this fails, the page says why and shows the
line to add by hand.

**Precedence.** Because the Include comes first, the values of a managed host
win over everything below it. Fields you leave empty fall through to your
`Host *` blocks and global options as usual, and forwards and identity files
from other blocks are added to the managed ones. A host defined in
`omassh.config` and also by hand in another file is shown as defined in both,
is read-only in the editor, and can only be deleted (which removes the managed
block alone). A new or renamed host cannot take a name that another file
defines (`taken`).

**Incomplete reads.** The name check and the read-only marking are only as good
as the parse of your config. When the plugin could not follow part of it, a host
defined there could be shadowed without a word. That happens for an `Include`
with `$` or `%`, a nesting deeper than 5, more than 50 files, a file that is
unreadable or over 1 MiB, more than 2000 hosts, 5000 `Host`/`Match` blocks or
5000 forward lines, and a config too complex to resolve. While it lasts the
panel shows a banner, every host is read-only and `host save` is refused with
`incomplete`; `omassh list` reports `editor.incomplete`. Delete still works but
treats the name as defined elsewhere: it neither stops a tunnel nor forgets the
pin or the recent entry. Fix or shorten the part of the config that cannot be
read.

**Fields**

| Field | Rule |
| --- | --- |
| Name (`Host`) | required, `[A-Za-z0-9][A-Za-z0-9._-]*`, 128 characters at most, case-sensitive, unique. Without an address it must not be a number-only name such as `9`, which ssh reads as an IP |
| Address (`HostName`) | optional, a name or IPv4 address (253 characters at most), or an IPv6 address without brackets or zone id. Stored lowercase |
| User | optional, `[A-Za-z0-9._][A-Za-z0-9._-]*`, 64 characters at most (no leading `-`, no `@`) |
| Port | optional, 1 to 65535, no leading zeros |
| Jump hosts (`ProxyJump`) | optional, 1 to 8 hops separated by commas, each `[user@]host[:port]` with an IPv6 host in brackets (1024 characters at most). `none`, `ssh://` URIs and a hop through the host itself are refused, and so is a chain that leads back to the host through other hosts of your config (`cycle`, read from the parse: managed and hand-written hosts alike) |
| Key file (`IdentityFile`) | optional, an absolute path or one starting with `~/`, segments of `[A-Za-z0-9._+@-]`, no `.` or `..`, 1024 characters at most. It must exist as a file (or a link to one) when you save: a typo would otherwise be skipped by ssh without a word. One per host |
| Forwards | optional, one per row, 16 at most, 300 characters per row, no duplicates |

Forward rows:

| Row | Becomes |
| --- | --- |
| `L 8080 localhost:80` | `LocalForward 8080 localhost:80` |
| `R 9000 localhost:22` | `RemoteForward 9000 localhost:22` |
| `R 9001` | `RemoteForward 9001`, a remote SOCKS proxy |
| `D 1080` | `DynamicForward 1080` |

The kind letter may be lowercase. The listen address is a bare port or
`localhost`, `127.0.0.1` or `[::1]` with a port; the target is a name, an IPv4
address or a bracketed IPv6 address with a port. A bare port binds the way ssh's
`GatewayPorts` says, which is loopback only unless you changed it. Only TCP
forwards exist.

Anything outside these grammars is rejected: whitespace, quotes, `#`, `\`, `%`,
`$`, `=`, non-ASCII text and control characters cannot be typed or pasted into
a value. The form shows the error under the field. The backend is the only
validator; the form adds only length limits. A host file holds at most 200
hosts and 256 KiB.

**File format.** Canonical, ASCII, LF, fixed order, four-space indent:

```
# OmaSSH host file. Edit these hosts in the OmaSSH panel; a hand edit makes the panel leave this file alone.

Host web
    HostName web.example.com
    User admin
    Port 2222
    ProxyJump bastion,admin@jump.example.com:2200
    IdentityFile ~/.ssh/id_ed25519
    LocalForward 8080 localhost:80
    RemoteForward 9000 localhost:22
    DynamicForward 1080

Host db
    HostName 192.0.2.5
```

Empty fields are left out. The panel treats the file as its own only when
rendering what it parsed gives back the same bytes. After any hand edit (a
comment, a reordered line, a different indent, a keyword the form cannot
express) the file is `foreign`: ssh still reads it and the hosts are listed, but
they are read-only, the panel never rewrites the file, and the banner offers
"Open omassh.config". Make it canonical again, or move it aside, to get the
editor back. A file that is a symlink, not a regular file, owned by someone
else, group- or world-writable, or over 256 KiB is `unsafe`; the panel leaves
it alone and says why. For a writable-by-others file it shows `chmod 600
~/.ssh/omassh.config`, because ssh itself refuses such a file for every host.

**Saving.** One save, under a lock shared by all panels and CLI calls:

1. The request is validated again and the alias is checked against the whole
   parsed config.
2. The new file is written to `.omassh.config.<random>.tmp` in `~/.ssh` (`0600`,
   created exclusively, never following a link) and synced.
3. `ssh -G -F <that temporary file> -- <alias>` is run on it, and its output is
   compared with the intended values (address, port, user, jump hosts, key,
   every forward). The exit status alone is not trusted, and empty output is a
   failure. ssh's refusal message is shown in the panel. It is never run on
   `~/.ssh/config`: a `Match exec` there would execute.
4. The file is checked once more to be the one that was read (device, inode,
   size, modification time).
5. Only then the previous bytes are kept in `omassh.config.bak` (one rolling
   copy), the temporary file is renamed over `omassh.config` and the directory
   is synced.

A failure at any step removes the temporary file and leaves `omassh.config`
unchanged; a refused save, a conflict included, leaves the backup alone. Saving needs `ssh`; without it the save fails and nothing is written.
Deleting does not run ssh.

**Two panels or scripts.** Edit and delete carry the fingerprint of the host
block they started from; a host that changed in between gives `conflict` and
the panel asks you to reopen it. Adding needs the name to be free. Edits to
different hosts never conflict.

**Delete, rename and tunnels.** Delete asks first; the default button is
Cancel. If the host's tunnel is up and only `omassh.config` defines the name
(origin `managed`, config read completely), it is stopped (through the same
verified stop as `x`) before the block is removed, and the confirmation says
so. When a hand-written host of the same name exists, which is what ssh reads
while the Include is not active, or the parse is incomplete, the tunnel is left
running. The pin and the recent entry of a host are forgotten once nothing in
your config defines that name any more and the config was read completely. Renaming moves the pin and the recent entry to the
new name, and is refused while the old name has a tunnel up. Editing a host
whose tunnel is up works, but the tunnel keeps its old forwards: the panel tells
you to restart it.

### Command line

```
omassh list [--config PATH]                          # hosts, tunnels, tools and saved commands as JSON
omassh probe [--config PATH] [ALIAS ...]             # TCP reachability as JSON
omassh connect [--config PATH] [--sftp | --tmux | --copy-id | --run ID] [--] ALIAS
omassh copy [--config PATH] [--target] [--] ALIAS    # ssh command, or user@host, to the clipboard
omassh code [--] ALIAS                               # VS Code Remote
omassh command-text [--alias ALIAS] [--] ID          # print a saved command (used by the session script)
omassh commands edit                                 # create commands.json if missing, open it in the editor
omassh tunnel start [--config PATH] [--] ALIAS       # JSON result
omassh tunnel stop [--] ALIAS | --all                # JSON result
omassh tunnel list                                   # running tunnels as JSON
omassh pin [--config PATH] [--] ALIAS
omassh unpin [--] ALIAS
omassh host validate                                 # check a host request read from stdin; writes nothing
omassh host save                                     # add, edit or rename a host from a request on stdin
omassh host delete --expect HEX [--] ALIAS           # remove a host of omassh.config
omassh include status                                # how ssh reads omassh.config, and the line apply would insert
omassh include apply --confirm --expect HEX          # insert the Include line into ~/.ssh/config
```

`connect` opens a terminal through `omarchy-launch-tui`, or
`xdg-terminal-exec` when that is missing. `--tmux` runs `tmux new-session -A -s omassh`
on the remote host. `code` ignores `configPath`: VS Code reads your default
SSH config.

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | success |
| 2 | usage error, an unsafe `--config`, or `tunnel stop` without exactly one of an alias and `--all`; a malformed `host` request, also an unreadable or closed stdin (`reason: "usage"`, with the JSON reply); `include apply` without `--confirm` and `--expect`, or a `--expect` that is not 16 hex digits. The command-line parser reports its own argument errors as usage text on stderr, without JSON |
| 3 | not a valid alias, or an alias not in your config; a saved command that does not exist or is not allowed for the host; the saved commands file or path cannot be used (`commands edit` also exits 3 for a dangling symlink, a directory or a file owned by someone else at the path); `host` field errors (`invalid`) or a host that `omassh.config` does not define (`not-managed`) |
| 4 | a needed tool or launcher is missing or failed: terminal launcher, `ssh-copy-id`, `wl-copy` (also when it does not finish within 2 seconds), `code`, or `omarchy` for the editor; or the plugin folder path is not made of shell-neutral characters; `host save` without `ssh` (`ssh-missing`) |
| 5 | the tunnel did not start (including the limit of 64), or the state directory cannot be used |
| 6 | a host or Include change was refused. `reason` is one of `not-included` (ssh does not read the file first), `incomplete` (part of your SSH config could not be read, see [Host editor](#host-editor)), `foreign` (edited by hand), `unsafe` (a file or directory is not safe to change), `conflict` (it changed since it was read), `tunnel-up` (rename with a tunnel up), `tunnel-running` (the tunnel would not stop), `ssh-rejected` (ssh refused the generated file), `check-failed` (ssh's answer did not match, or timed out), `limit` (200 hosts or 256 KiB) or `io` |

#### Host commands

`host validate` and `host save` read one request from stdin: a single line of
JSON, 64 KiB at most, finished by a newline and sent within 5 seconds. Field
values never travel on the command line, where other users could read them in
`/proc` and a value starting with `-` could pass for an option. `host delete`
takes only the fingerprint and, after `--`, the alias.

```json
{"version":1,"original":"","expect":"","host":{"alias":"web","hostname":"web.example.com","user":"admin","port":"2222","proxyJump":"","identityFile":"","forwards":["L 8080 localhost:80"]}}
```

The request must have exactly these keys, and every value must be a string
(`forwards` a list of strings). Unknown or repeated keys, other types and bad
JSON exit 2. `original` is empty for a new host, or the current name when
editing or renaming; `expect` is empty for a new host, or the `expect`
fingerprint that `omassh list` reports for that host (16 hex digits, the start of
the SHA-256 of its block). `host delete` takes the same fingerprint.

Every reply is one line of ASCII JSON on stdout with `"version":1`. A failure
has `"ok":false`, a `reason` and a `message` of 200 characters at most.

| Reply | Fields |
| --- | --- |
| `host save` ok | `ok`, `alias`, `created`, `renamed`, `tunnelUp` (the host was edited in place and its tunnel is up) |
| `host validate` ok | `ok`, `alias` |
| `host delete` ok | `ok`, `alias`, `tunnelStopped`, `forgotten` (pin and recent entry removed) |
| `reason: "invalid"` | `errors`: a list of `{"field", "code"}` (and `"index"` for a forward row). Codes: `required`, `too-long`, `invalid`, `port`, `too-many`, `duplicate`, `taken`, `not-found`, `self`, `forward`, `hop`, `cycle` |
| `reason: "not-included"` | also `include` and `where`: the state of the Include line |
| `reason: "incomplete"` | nothing was written; the message says part of the config could not be read |

`include status` prints `include` (`missing`, `active`, `late` or `scoped`),
`where` (`file` and `line` of the Include line, or null), `path`, `target` (the
symlink target, empty when there is none), `create` (the file does not exist),
`line` (where the line would go), `insert`, the cleaned context lines `before`
and `after`, `expect` (the fingerprint to pass to `apply`) and `refusal`
(`""`, `not-regular`, `owner`, `mode`, `links`, `dir`, `too-large`, `bom`,
`group`, `managed-unsafe` or `managed-foreign`). `include apply` needs both
`--confirm` and `--expect` (without them it exits 2 and changes nothing) and
prints `ok`, `changed`, `backup` and `include`; when the line is already
effective it reports `changed: false`. It refuses with `reason: "unsafe"` and
the same `refusal` code when the host file is not missing or canonical, and also
when the group of the file cannot be kept at the moment of the rename (`group`).
`host validate` checks the fields and the names only; the `incomplete` refusal
belongs to `host save`.

`omassh list` is version 3: each host has `origin` (`config`, `managed` or
`both`) and `editable`, and the reply has an `editor` object with `enabled`,
`file` (`missing`, `ok`, `foreign` or `unsafe`), `fileReason`, `include`,
`where`, `incomplete`, `path`, `count` and `hosts` (the fields of each host stored in
`omassh.config` plus its `expect`; empty unless `file` is `ok`). With
`--config` it is just `{"enabled": false}`.

The popup only calls this CLI and the editor launcher. To use it from your shell, link it:
`ln -s ~/.config/omarchy/plugins/paulorivera27.omassh/omassh ~/.local/bin/omassh`.
Pins, recent hosts and tunnel records live in `~/.local/state/omassh/state.json`
(under `$XDG_STATE_HOME` when it is an absolute path).

## What it does *not* do

- It does not store passwords, keys or passphrases. Use keys and `ssh-agent`.
- It writes only two things in `~/.ssh`: hosts you add, edit or delete in the
  panel go to `omassh.config`, which it owns, and, once, after a preview and
  your confirmation, it inserts the single line `Include ~/.ssh/omassh.config`
  into `~/.ssh/config` with a backup first. It never edits another line of
  your SSH config or any other file you wrote, and it does not edit anything
  while `configPath` is set. Hosts you wrote by hand are edited in their file
  (the pencil button opens it).
- It does not change SSH's security settings: no `StrictHostKeyChecking`, no
  custom `known_hosts`. Host-key prompts appear in the terminal as usual.
- It does not run anything on a timer, apart from a 5 second watchdog that
  exists only while a host or Include command is in flight, and does not touch
  the network until you ask for a reachability check (or turn on `autoProbe`) or start a tunnel.
- It does not start tunnels on its own, restart them, or keep them alive.
- It does not run saved commands locally, and it does not write to
  `commands.json` beyond creating it empty when it is missing.

## Security model

Your SSH config is a trusted file you wrote, but the plugin treats everything it
reads as untrusted text, because configs get copied from elsewhere and a host
name ends up on a command line.

| Risk | How it is handled |
| --- | --- |
| A host called `-oProxyCommand=...` becomes an ssh option | Aliases must match `[A-Za-z0-9][A-Za-z0-9._-]{0,127}` (never a leading `-`, no `@`, no spaces or shell characters). Others are skipped and counted ("N hosts skipped"). `--` always precedes the alias. |
| A crafted alias or path runs a command | No shell is involved: the terminal is started from an argument list (`Quickshell.execDetached([...])`, `subprocess.Popen([...])`) and the session script quotes `"$alias_name"`. On top of that, every value that reaches that list (alias, config path, the plugin folder's own path) is limited to characters a shell treats as plain text, so it stays safe even in a terminal that joins its arguments into a shell string; `connect` refuses to start a terminal from a plugin folder whose path is not (exit 4). The QML starts only the `omassh` CLI and the editor launcher (`omarchy launch editor`); the CLI starts everything else through `backend/launch.py`, and `session.sh` starts ssh, sftp and ssh-copy-id. The QML never names those as programs. |
| The UI is tricked into connecting somewhere else | Commands that launch or start something (`connect`, `copy`, `code`, `tunnel start`) and `pin` accept only a valid alias that exists in the parsed config. `unpin`, `tunnel stop` and `command-text` check the format only, so a host removed from the config can still be cleaned up. The session script re-validates the alias. |
| Text in the config renders as markup / spoofs the display | Every `Text` is `PlainText` (enforced by a test). Displayed values lose control, bidi-override and line-separator characters and are length-capped. |
| Huge or hostile files, include loops | 1 MiB per file, 50 files, `Include` depth 5, 2000 hosts, 5000 `Host`/`Match` blocks, 5000 forward lines, cycle detection; FIFOs and devices are refused; `Include` patterns containing `%` or `$` are not expanded. Whenever an `Include` is skipped or a cap is hit, every host is marked as possibly having forwards that are not shown, is not probed, and offers no `user@host` to copy; the host cap counts too. The editor also stops saving while the parse is incomplete. |
| A tampered state file | Size-capped (256 KiB), every alias, timestamp and tunnel record re-validated, corrupt files moved aside; written atomically with `0600`/`0700` permissions under a lock. |
| Reachability checks leak activity or bypass your route | Off by default, only on request, connect-and-close with no data sent, ~1.5 s per host, 8 s total. A host that goes through a jump host or proxy command is never probed directly, whether that is set on the host, inherited from a wildcard `Host` block, global, or pulled in by `Include`. If a `Match` block could change where a host connects, or part of the config could not be read (a skipped `Include`, a cap), no host is probed. |
| Forward text from the config ends up on a command line | It does not. The tunnel is `ssh -N -f` with a fixed option list and the alias after `--`; ssh reads the forwards from the config itself. A test checks that hostile forward text never reaches argv. |
| A tunnel hangs on a prompt or hijacks a session | `BatchMode=yes`, `SSH_ASKPASS_REQUIRE=never`, no terminal, `ControlMaster=no`, `ControlPath=none`, `RemoteCommand=none`, `PermitLocalCommand=no`, `ExitOnForwardFailure=yes`, and a 20 s timeout after which the whole process group is killed (members that ignore SIGTERM get SIGKILL). The jump host's ssh does not inherit these options; see [Tunnels](#tunnels). |
| A stop signal reaches the wrong process | A record holds pid, process start time and boot id. Before listing or stopping, the process must match all three, belong to you, and have exactly the command line the plugin would have started. The signal goes through a pidfd opened before the check. A tampered state file therefore cannot make the plugin signal an unrelated process. |
| A planted agent socket | `SSH_AUTH_SOCK` is only set, and only when it is unset, from `$XDG_RUNTIME_DIR/ssh-agent.socket` when that is a socket you own. |
| A saved command is swapped or leaks onto an argv | The terminal argv carries only the command's id, never its text. The panel receives the id, the name and an 80-character preview of the text (a short command is shown whole). The session script asks `omassh command-text` for the text, which re-reads the file, checks the id against a hash of name and text, checks the host restriction, and prints nothing otherwise. |
| A hostile or oversized commands file | Must be a regular file you own and not group- or world-writable, at most 64 KiB and 50 entries. Names and commands are length-capped single lines without control or separator characters; invalid or duplicate entries are skipped and counted. The text runs through `ssh -t` on the remote host, never locally. |
| The clipboard receives something unexpected | `wl-copy` is started from an argument list with `--`. The text is built from a validated alias and config path; `user@host` is only offered when the user and host match a conservative pattern. Nothing is pasted or executed. |
| `omassh commands edit` clobbers or follows something | The file is created with `O_CREAT\|O_EXCL\|O_NOFOLLOW` as `0600` in a `0700` directory it creates. An existing file is never opened for writing, `chmod`-ed or overwritten. A symlink to a regular file you own is accepted; a dangling symlink, a directory, a FIFO or a file owned by someone else is refused (exit 3). |
| Interpreter / path hijacking | The CLI runs `python3 -I -B`: no `PYTHONPATH`, no current-directory imports, no bytecode written into the plugin folder. |
| A host value injects ssh options or a second line (`a ProxyCommand x`, newline, `#`, quotes, `\`, `=`, `%h`, `${VAR}`, bidi or zero-width text) | Every field is checked with a whitelist grammar over ASCII, matched in full; the only trimming is of spaces and tabs. No value can hold whitespace, `#`, quotes, `\`, `%`, `$` or `=`, so a line never gets a second argument or a comment and ssh never expands anything. The keywords come from a fixed table of nine (`Host` and eight options); code-executing keywords (`ProxyCommand`, `LocalCommand`, `Match`, `Include`, `SetEnv`, ...) cannot be produced, which tests enforce on the source. The rendered file is parsed back before it is written and must equal the intended hosts. |
| A `ProxyJump` hop becomes an option or a shell command | ssh accepts hops such as `-oProxyCommand=x` or `b;touch` when it only parses the file, and turns each hop into a shell command line for the jump connection. A hop is therefore parsed structurally: no leading `-`, a host of letters, digits, `.`, `_` and `-` or a bracketed IPv6 address, an optional `user@` and `:port`, at most 8 hops. `none` and `ssh://` are refused. |
| A forward exposes a service to the network | The listen address is a bare port or loopback, never `*` or a LAN address; there are no unix-socket forwards. A bare port follows ssh's `GatewayPorts`. |
| A symlink, FIFO or swapped path at `omassh.config`, its backup, a temporary name or `~/.ssh/config` | `~/.ssh` is opened once as a directory descriptor and must be yours and closed to group and others; every later operation is relative to it. Files are read with `O_NOFOLLOW` and must be regular, yours, not group- or world-writable and under the size cap (`~/.ssh/config`: also single-linked, no byte order mark). Temporary files and the main-config backup are created with `O_EXCL` and `O_NOFOLLOW` under random names; the rename replaces a link instead of following it. A symlinked `~/.ssh/config` is followed only after the checks listed under [Host editor](#host-editor). |
| A lost update, between two panels or against another editor | One lock covers every host or Include change; edits carry a fingerprint of the block they started from; the device, inode, size and modification time are compared just before the rename and a difference is refused as a conflict. The window between that check and the rename cannot be closed against a program that ignores the lock. |
| A crash or a bad write leaves a broken file | Temporary file, `fsync`, rename, directory `fsync`. Any failure removes the temporary file and leaves the old file. |
| `omassh.config` with unsafe permissions breaks every host | The plugin writes it as `0600`, refuses to change it when it is writable by group or others or owned by someone else, shows the `chmod 600` command, and `include apply` refuses while it is unsafe. `ssh -G -F` cannot catch this by itself: ssh does not permission-check a file passed with `-F`. |
| `ssh -G` runs code or is fooled | It runs only as `ssh -G -F <generated candidate> -- <alias>`: the candidate has no `Match`, `Include` or `ProxyCommand`, and `-F` skips the system config. It is never run on `~/.ssh/config`. 5 second timeout (the child is killed and reaped), output capped at 64 KiB. Its exit status is not trusted: the output is compared option by option with what was meant, and empty or different output refuses the save. |
| A hand-written host is shadowed or edited by mistake | A host is editable only when the parse shows it defined in `omassh.config` alone, the file is canonical and safe and the Include is active. The CLI recomputes this under the lock for every request; the panel only mirrors it. A name that any other file defines is refused (`taken`), and so is every save while the parse is incomplete (a skipped `Include`, a cap, a config too complex to resolve): the name could be defined where the plugin cannot see. Delete removes only the managed block and, then, neither stops a tunnel nor forgets a pin. |
| The Include line lands where it does not take effect, or damages the main config | One line is inserted at a byte offset; the rest of the file is copied byte for byte, never decoded and re-encoded. The candidate is parsed with the plugin's own parser and must come out active before it replaces the file. Preview and fingerprint, a backup in `~/.ssh`, refusals for another owner, group- or world-writable files, hard links, a byte order mark, files over 1 MiB and unsafe directories. The owner, the group and the mode are kept and the mode is never widened; when the group cannot be kept the change is refused. The host file must be missing or canonical, checked at preview, at apply and before the rename. |
| A hostile paste or tampered list data reaches the UI | A pasted value is data in a text field: it cannot become a key press, a flag or markup (every `Text` is `PlainText`), and the backend rejects what the grammars do not allow. The panel type-checks and length-limits the `editor` data it gets from the CLI. |
| A request blocks the CLI or exhausts it | One line, 64 KiB, 5 seconds, strict UTF-8 and JSON, exact keys. At most 200 hosts, 16 forwards per host, 8 hops, a 256 KiB file. |
| Deleting or renaming a host leaves a tunnel or state behind | A delete stops the host's tunnel through the verified pidfd path first, only when `omassh.config` alone defines the name, and refuses if it keeps running. A rename is refused while the tunnel is up. Pins and recents are removed or moved only when the old name is no longer defined anywhere and the config was read completely. |

What the plugin cannot protect against: a hostile `Match exec` or
`ProxyCommand` in your own config still runs when *ssh* connects (that is
ssh's behaviour, not something the plugin adds), a saved command is executed by
the remote shell exactly as you wrote it, and anyone who can already edit
`~/.ssh/config`, the saved commands file or the plugin folder can do worse
than anything here. OmaSSH never evaluates `Match` conditions and never runs
`ssh -G` on your config: it runs it only with `-F` on the file it generates
when you save a host.

### Limitations

- `Match` conditions are not evaluated (that would mean running `ssh -G` on
  your config, which executes `Match exec`). A `Match` block's options are not
  shown, and if one
  could change `HostName`, `Port` or a proxy setting, reachability checks are
  switched off for every host. Forwards added by a `Match` block are not shown
  either; the actions page says so, and the tunnel starts anyway.
- `Include` patterns that use `%` tokens or `$VARIABLES` are not followed, and
  neither are includes nested deeper than 5 levels, past 50 files, unreadable
  or over 1 MiB. Any of these, or the 5000-forward-line cap, marks every host
  as possibly having forwards that are not shown, switches off reachability
  checks and hides `user@host` copying, because the skipped text may hold
  forwards, a jump host, a host name or a user. The same holds for the 2000-host
  cap. The host editor refuses to save while any of this applies.
- Aliases outside the whitelist (for example `my host` or `a@b`) are skipped,
  not listed - the panel says how many.
- One tunnel per host, carrying all of its forwards. You cannot start a single
  forward.
- Errors after ssh has gone to the background are not shown. A tunnel that dies
  is dropped from the list the next time it is checked.
- One malformed forward line anywhere in the config makes ssh reject the
  config for every host, not only the one it sits under. The plugin does not
  validate forward text you wrote by hand, so the tunnel fails with ssh's
  message. Forwards saved from the panel are validated first.
- A tunnel carries every forward of its host, including those inherited from
  shared blocks such as `Host *`. Connecting to another host while a tunnel is
  up does not drop them, so the same ports can be bound twice: ssh warns, or
  fails under `ExitOnForwardFailure yes`.
- A `Match` block elsewhere in `~/.ssh/config` still applies to managed hosts,
  and the editor does not evaluate it: it can fill fields the form leaves empty
  and add forwards or identity files. The `ssh -G` check sees only
  `omassh.config`, so it cannot report such a block.
- The editor does not take IPv6 zone ids (`fe80::1%eth0`), unix-socket
  forwards, a listen address other than a bare port or loopback, `ssh://` jump
  hosts, `ProxyJump none` or more than one `IdentityFile` per host. A host
  name made only of numbers, such as `9` or `010.1`, is rejected as an
  address, a jump hop, a forward target and as a name without an address,
  because ssh reads it as an IP in another form. Use the dotted four-number
  form or a real name.
- The key file is checked when you save. If you delete it later, ssh skips it
  without an error.
- Adding the Include line replaces `~/.ssh/config` with a new file (a rename).
  Extended attributes and ACLs of the old file are not carried over; the owner,
  the group and the mode are kept. An editor that still holds an old
  buffer of the file can overwrite the inserted line when it saves: close it
  first.
- A `kill -9` during a write can leave a temporary file named
  `.<file name>.<random>.tmp` behind, in `~/.ssh` or beside the symlink target.
  It is harmless: ssh never reads it, and you can delete it.
- The plugin assumes that `$HOME` is the home directory of the password
  database, which its tests also rely on. It reads `~/.ssh/config` and
  `~/.ssh/omassh.config` and checks `~/` key files through `$HOME`, while ssh
  finds its default config and expands `~/` in `IdentityFile` through the password
  database; `~` in an `Include` goes through `$HOME`. If the two differ, ssh
  and the panel can read different files.
- A bracketed IPv6 jump hop that is not the last one reaches ssh's `sh -c`
  template unquoted. The grammar leaves no way to inject anything, but the
  character class can match files in ssh's working directory.
- Line endings follow ssh: only a newline ends a line, and a trailing carriage
  return is dropped. A carriage return, vertical tab, form feed, NEL or U+2028
  inside a comment is part of the comment. ssh rejects a vertical tab or form
  feed at the start of a directive, a carriage return inside one, and the plugin
  reads such a file leniently where ssh would refuse it as a whole.
- Saving a host needs `ssh`; deleting does not.
- VS Code ignores `configPath`, so the action is hidden when it is set.
- Saved commands run in the terminal's environment. If the terminal has a
  different `XDG_CONFIG_HOME` than the shell that runs the bar, `run` looks in
  another place and refuses, without running anything.
- The bar icon is drawn pixel by pixel; fractional output scaling can blur it.
- Only foot has been exercised end to end as the terminal. Other terminals
  that run `-e <command> <args...>` should work, but that is untested.

## Development

```bash
python3 -I -B -m unittest discover -s tests -v   # unit + end-to-end + security guardrails
                                                   # (+ comparison with the real `ssh -G`, if ssh is installed)
omarchy plugin validate .                          # manifest check
```

Layout:

```
manifest.json        plugin manifest
BarWidget.qml        the bar icon (hosts the popup, IPC target)
Panel.qml            the popup: host list, actions page, host form and Include setup
HostForm.qml         the host form (fields and keys only; Panel.qml runs the CLI)
i18n/                strings: en.json, es.json, ja.json
omassh               CLI wrapper (python3 -I -B)
backend/             sshconfig.py (parser), store.py (pins, recents, tunnel records),
                     tunnels.py (background tunnels), commands.py (saved commands),
                     hostform.py (host fields, file format, ssh -G expectations),
                     safefile.py (descriptor-relative reads, atomic installs),
                     hostfile.py (omassh.config state and writes), mainconfig.py (the Include line),
                     launch.py (the only place the backend starts a process), probe.py, cli.py
scripts/session.sh   runs inside the terminal window
tests/               unit tests per module (including test_hostform, test_safefile, test_hostfile
                     and test_mainconfig for the editor), CLI end-to-end (fake launchers on a
                     sandboxed PATH, HOME and XDG dirs), session script tests, differential
                     tests against `ssh -G`, security guardrails (test_repo.py)
```

To add a language, copy `i18n/en.json` to `i18n/<code>.json` (codes are listed in
Omarchy's `default/i18n/locales.json`), translate the values and keep the `%1`
placeholders, the shortcut letters and the command and product names listed in
`LocaleTests.TOKENS` (`ssh`, `sftp`, `tmux`, `ssh-copy-id`, `VS Code`, ...).
Plural entries need the categories of the language; add the code and its
categories to `LocaleTests.REQUIRED` in `tests/test_repo.py`, which checks all of it.

Omarchy caches compiled QML: after editing a `.qml` file, restart the shell
(`omarchy restart shell`) to see the change. JSON and scripts are re-read live.

## License

MIT - see [LICENSE](LICENSE).
