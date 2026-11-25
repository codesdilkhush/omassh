import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Commons as Commons
import qs.Ui

Panel {
  id: root
  moduleName: "io.github.paulorivera27.omassh"
  ipcTarget: "io.github.paulorivera27.omassh"
  manageIpc: false

  property var anchorItem: null
  property var hostWidget: null
  readonly property var barIdentity: hostWidget || root

  readonly property string pluginDir: decodeURIComponent(
    String(Qt.resolvedUrl(".")).replace(/^file:\/\//, "")).replace(/\/$/, "")
  readonly property string cli: pluginDir + "/omassh"

  readonly property bool autoProbe: root.setting("autoProbe", false) === true
  readonly property var configArgs: {
    var path = root.setting("configPath", "")
    return (typeof path === "string" && path !== "") ? ["--config", path] : []
  }

  property var hosts: []
  property var reach: ({})
  property string configPath: ""
  property bool loaded: false
  property bool loadFailed: false
  property bool sshFound: true
  property int skipped: 0
  property var errors: []
  property bool probing: false
  property bool probed: false

  property var tools: ({ wlCopy: false, sshCopyId: false, code: false })
  property var commands: []
  property string commandsPath: ""
  property string commandsError: ""
  property int commandsSkipped: 0

  property var tunnelMap: ({})
  property int activeTunnels: 0
  property string tunnelBusyAction: ""
  property string tunnelBusyAlias: ""
  property var tunnelErrors: ({})
  property string actionError: ""
  property bool editPending: false
  property bool tunnelRefreshPending: false
  property bool listRefreshPending: false

  property var editor: ({ enabled: false, hosts: [] })
  property string formMode: ""
  property string formOriginal: ""
  property string formExpect: ""
  property var fieldErrors: []
  property string formError: ""
  property string notice: ""
  property string editorError: ""
  property bool savePending: false
  property bool deletePending: false
  property string includeMode: ""
  property var setup: root.emptySetup()
  property string setupError: ""
  property bool deleteConfirmOpen: false
  property string deleteAlias: ""
  property string deleteExpect: ""
  property bool deleteTunnel: false
  property int pendingTicks: 0

  property string query: ""
  property int cursor: 0
  property string pendingAlias: ""

  property string page: "hosts"
  property string actionAlias: ""
  property int actionCursor: 0

  readonly property color fg: root.barForeground
  readonly property color dim: Qt.darker(root.barForeground, 1.5)
  readonly property string fontFamily: Style.font.family

  readonly property var shown: {
    var q = root.query.trim().toLowerCase()
    if (q === "") return root.hosts
    var out = []
    for (var i = 0; i < root.hosts.length; i++) {
      var h = root.hosts[i]
      var hay = (h.alias + " " + h.hostname + " " + h.user).toLowerCase()
      if (hay.indexOf(q) !== -1) out.push(h)
    }
    return out
  }

  readonly property var actionHost: {
    for (var i = 0; i < root.hosts.length; i++)
      if (root.hosts[i].alias === root.actionAlias) return root.hosts[i]
    return null
  }
  readonly property var actionRows: root.actionsFor(root.actionHost)
  readonly property string tunnelStatus: root.statusText()
  readonly property bool editorOn: root.editor.enabled === true && root.configArgs.length === 0
  readonly property bool editorBusy: root.savePending || root.deletePending || root.includeMode !== ""
  readonly property var banner: root.editorBanner()
  readonly property var setupLines: root.contextLines(root.setup)
  readonly property var translations: strings

  Commons.Translations { id: strings; directory: Qt.resolvedUrl("i18n") }

  /** Returns value cut to limit characters, or an empty string when it is not a string. */
  function str(value, limit) {
    return typeof value === "string" ? value.substring(0, limit || 255) : ""
  }

  /** Returns the key under which per-host values are stored, so no alias can collide with a property of Object. */
  function aliasKey(alias) {
    return "h:" + alias
  }

  /** Returns value as a whole number between 0 and max, or 0 when it is not a number. */
  function whole(value, max) {
    return (typeof value === "number" && value > 0) ? Math.min(Math.floor(value), max) : 0
  }

  /** Returns the port forwards of a host as a short list of kind, listen and target. */
  function parseForwards(list) {
    var out = []
    if (!Array.isArray(list)) return out
    for (var i = 0; i < list.length && i < 32; i++) {
      var f = list[i]
      if (!f || (f.kind !== "L" && f.kind !== "R" && f.kind !== "D")) continue
      out.push({ kind: f.kind, listen: str(f.listen, 128), target: str(f.target, 128) })
    }
    return out
  }

  /** Returns the saved commands with an id, a name, a preview and the hosts they are limited to. */
  function parseCommands(list) {
    var out = []
    if (!Array.isArray(list)) return out
    for (var i = 0; i < list.length && i < 50; i++) {
      var c = list[i]
      if (!c || typeof c.id !== "string" || !/^[0-9a-f]{16}$/.test(c.id) || typeof c.name !== "string") continue
      var hosts = null
      if (c.hosts !== null && c.hosts !== undefined) {
        hosts = []
        if (Array.isArray(c.hosts))
          for (var j = 0; j < c.hosts.length && j < 200; j++)
            if (typeof c.hosts[j] === "string") hosts.push(str(c.hosts[j], 128))
      }
      out.push({ id: c.id, name: str(c.name, 80), preview: str(c.preview, 120), hosts: hosts })
    }
    return out
  }

  /** Returns the error code of the saved commands file, limited to the known codes. */
  function parseCommandsError(value) {
    if (typeof value !== "string" || value === "") return ""
    return (value === "insecure" || value === "too-large" || value === "not-regular") ? value : "invalid"
  }

  /** Returns true when value is a string of at most limit characters. */
  function within(value, limit) {
    return typeof value === "string" && value.length <= limit
  }

  /** Returns the position of the Include line in the main config, or null when it has none. */
  function parseWhere(value) {
    if (!value || typeof value !== "object" || typeof value.file !== "string") return null
    return { file: str(value.file, 80), line: whole(value.line, 10000000) }
  }

  /** Returns a host of the plugin file with every field checked, or null when one is out of bounds. */
  function parseEditorHost(h) {
    if (!h || typeof h !== "object" || !root.within(h.alias, 128) || h.alias === "") return null
    if (typeof h.expect !== "string" || !/^[0-9a-f]{16}$/.test(h.expect)) return null
    if (!root.within(h.hostname, 253) || !root.within(h.user, 64) || !root.within(h.port, 5)) return null
    if (!root.within(h.proxyJump, 1024) || !root.within(h.identityFile, 1024)) return null
    if (!Array.isArray(h.forwards) || h.forwards.length > 16) return null
    var forwards = []
    for (var i = 0; i < h.forwards.length; i++) {
      if (!root.within(h.forwards[i], 300)) return null
      forwards.push(h.forwards[i])
    }
    return { alias: h.alias, hostname: h.hostname, user: h.user, port: h.port, proxyJump: h.proxyJump, identityFile: h.identityFile, forwards: forwards, expect: h.expect }
  }

  /** Returns the host editor state printed by `omassh list`, or a disabled state when it is off or malformed. */
  function parseEditor(value) {
    var off = { enabled: false, hosts: [] }
    if (!value || typeof value !== "object" || value.enabled !== true) return off
    var files = ["missing", "ok", "foreign", "unsafe"]
    var reasons = ["", "symlink", "not-regular", "owner", "mode", "too-large", "dir", "io"]
    var includes = ["missing", "active", "late", "scoped"]
    if (files.indexOf(value.file) === -1 || reasons.indexOf(value.fileReason) === -1 || includes.indexOf(value.include) === -1) return off
    var hosts = []
    var list = Array.isArray(value.hosts) ? value.hosts : []
    for (var i = 0; i < list.length && hosts.length < 200; i++) {
      var entry = root.parseEditorHost(list[i])
      if (entry) hosts.push(entry)
    }
    return {
      enabled: true,
      file: value.file,
      fileReason: value.fileReason,
      include: value.include,
      where: root.parseWhere(value.where),
      incomplete: value.incomplete === true,
      path: str(value.path, 1024),
      count: whole(value.count, 200),
      hosts: hosts
    }
  }

  /** Returns the context lines of an include preview as a short list of strings. */
  function contextOf(list) {
    var out = []
    if (!Array.isArray(list)) return out
    for (var i = 0; i < list.length && i < 6; i++)
      if (typeof list[i] === "string") out.push(str(list[i], 120))
    return out
  }

  /** Returns the Include preview of a page that has not loaded yet. */
  function emptySetup() {
    return { loaded: false, include: "", where: null, path: "", target: "", create: false, line: 0, insert: "", before: [], after: [], expect: "", refusal: "", acl: false }
  }

  /** Returns the Include preview printed by `omassh include status`, or null when it is malformed. */
  function parseSetup(data) {
    var includes = ["missing", "active", "late", "scoped"]
    var refusals = ["", "not-regular", "owner", "mode", "links", "dir", "too-large", "bom", "group", "acl", "managed-unsafe", "managed-foreign"]
    if (includes.indexOf(data.include) === -1 || refusals.indexOf(data.refusal) === -1) return null
    if (!root.within(data.path, 1024) || !root.within(data.target, 1024) || !root.within(data.insert, 200)) return null
    if (typeof data.expect !== "string" || !/^(?:[0-9a-f]{16})?$/.test(data.expect)) return null
    return {
      loaded: true,
      include: data.include,
      where: root.parseWhere(data.where),
      path: data.path,
      target: data.target,
      create: data.create === true,
      line: whole(data.line, 10000000),
      insert: data.insert,
      before: root.contextOf(data.before),
      after: root.contextOf(data.after),
      expect: data.expect,
      refusal: data.refusal,
      acl: data.acl === true
    }
  }

  /** Returns the field errors of a rejected host, limited to the known fields and codes. */
  function parseFieldErrors(list) {
    var fields = ["alias", "hostname", "user", "port", "proxyJump", "identityFile", "forwards"]
    var codes = ["required", "too-long", "invalid", "port", "too-many", "duplicate", "taken", "not-found", "self", "forward", "hop", "cycle"]
    var out = []
    if (!Array.isArray(list)) return out
    for (var i = 0; i < list.length && i < 40; i++) {
      var e = list[i]
      if (!e || typeof e !== "object" || fields.indexOf(e.field) === -1 || codes.indexOf(e.code) === -1) continue
      var row = (typeof e.index === "number" && e.index >= 0 && e.index < 16) ? Math.floor(e.index) : -1
      out.push({ field: e.field, index: row, code: e.code })
    }
    return out
  }

  /** Returns the reply of a host or include command as an object, or null when it is empty, too long or not JSON. */
  function parseReply(text) {
    var output = String(text || "")
    if (output.length === 0 || output.length > 100000) return null
    var data = null
    try { data = JSON.parse(output) } catch (e) { data = null }
    return (data && typeof data === "object" && !Array.isArray(data)) ? data : null
  }

  /** Returns the failure reason of a reply, or an empty string. */
  function replyReason(data) {
    return data ? str(data.reason, 20) : ""
  }

  /** Returns the failure message of a reply, or an empty string. */
  function replyMessage(data) {
    return data ? str(data.message, 200) : ""
  }

  /** Applies the JSON printed by `omassh list`. */
  function applyList(text) {
    if (text.length > 4000000) { root.loadFailed = true; return }
    var data = null
    try { data = JSON.parse(text) } catch (e) { data = null }
    if (!data || !Array.isArray(data.hosts)) { root.loadFailed = true; return }

    var out = []
    for (var i = 0; i < data.hosts.length && i < 2000; i++) {
      var h = data.hosts[i]
      if (!h || typeof h.alias !== "string") continue
      out.push({
        alias: str(h.alias, 128),
        hostname: str(h.hostname),
        user: str(h.user, 64),
        port: (typeof h.port === "number" && h.port > 0 && h.port < 65536) ? Math.floor(h.port) : 0,
        jump: str(h.jump),
        proxy: h.proxy === true,
        pinned: h.pinned === true,
        forwards: parseForwards(h.forwards),
        forwardsMore: whole(h.forwardsMore, 100000),
        forwardsUncertain: h.forwardsUncertain === true,
        target: str(h.target, 320),
        origin: (h.origin === "managed" || h.origin === "both") ? h.origin : "config",
        editable: h.editable === true
      })
    }
    root.editor = root.parseEditor(data.editor)
    root.hosts = out
    root.configPath = str(data.configPath, 1024)
    root.sshFound = data.sshFound !== false
    root.skipped = (typeof data.skipped === "number") ? data.skipped : 0
    var errs = []
    if (Array.isArray(data.errors))
      for (var j = 0; j < data.errors.length && j < 5; j++)
        if (data.errors[j] && typeof data.errors[j].file === "string") errs.push(str(data.errors[j].file, 80))
    root.errors = errs
    var tools = (data.tools && typeof data.tools === "object") ? data.tools : ({})
    root.tools = { wlCopy: tools.wlCopy === true, sshCopyId: tools.sshCopyId === true, code: tools.code === true }
    root.commands = parseCommands(data.commands)
    root.commandsPath = str(data.commandsPath, 1024)
    root.commandsError = parseCommandsError(data.commandsError)
    root.commandsSkipped = whole(data.commandsSkipped, 100000)
    root.loadFailed = false
    root.loaded = true

    if (root.pendingAlias !== "") {
      for (var k = 0; k < root.shown.length; k++)
        if (root.shown[k].alias === root.pendingAlias) { root.cursor = k; break }
      root.pendingAlias = ""
    }
    root.clampCursor()
  }

  /** Applies the JSON printed by `omassh probe`. */
  function applyProbe(text) {
    if (text.length > 1000000) return
    var data = null
    try { data = JSON.parse(text) } catch (e) { return }
    if (!data || typeof data.results !== "object" || data.results === null) return
    var out = {}
    for (var alias in data.results) {
      var entry = data.results[alias]
      var state = entry && typeof entry.state === "string" ? entry.state : "unknown"
      out[root.aliasKey(alias)] = (state === "up" || state === "down") ? state : "unknown"
    }
    root.reach = out
    root.probed = true
  }

  /** Applies the JSON printed by `omassh tunnel list`. */
  function applyTunnels(text) {
    if (text.length > 100000) return
    var data = null
    try { data = JSON.parse(text) } catch (e) { return }
    if (!data || !Array.isArray(data.tunnels)) return
    var map = {}
    var count = 0
    for (var i = 0; i < data.tunnels.length && i < 64; i++) {
      var t = data.tunnels[i]
      if (!t || typeof t.alias !== "string") continue
      map[root.aliasKey(str(t.alias, 128))] = true
      count++
    }
    root.tunnelMap = map
    root.activeTunnels = count
  }

  /** Describes the user, host, port and jump host of a host in one line. */
  function detailFor(h) {
    var s = ""
    if (h.user !== "") s += h.user + "@"
    s += h.hostname
    if (h.port > 0) s += ":" + h.port
    if (h.jump !== "") s += " · " + strings.t("row.via", "via %1").arg(h.jump)
    else if (h.proxy) s += " · " + strings.t("row.viaProxy", "via proxy command")
    return s
  }

  /** Describes a port forward as its kind, listening address and target. */
  function forwardText(f) {
    return f.kind + "  " + f.listen + (f.target !== "" ? " → " + f.target : "")
  }

  /** Explains why the saved commands file cannot be used. */
  function commandsErrorText(code) {
    var path = root.commandsPath
    if (code === "insecure") return strings.t("commands.insecure", "The saved commands file is ignored because it is writable by others: %1").arg(path)
    if (code === "too-large") return strings.t("commands.tooLarge", "The saved commands file is too large: %1").arg(path)
    if (code === "not-regular") return strings.t("commands.notRegular", "The saved commands path is not a regular file: %1").arg(path)
    return strings.t("commands.invalid", "The saved commands file could not be read: %1").arg(path)
  }

  /** Explains why a tunnel did not start or stop. */
  function tunnelErrorText(entry) {
    if (entry.reason === "failed") {
      var hint = /address already in use|bind/i.test(entry.message) ? ""
        : "\n" + strings.t("tunnel.hint", "Tunnels cannot ask for passwords. Add your key to ssh-agent and connect once in a terminal to trust the host.")
      if (entry.message === "") return strings.t("tunnel.failedPlain", "The tunnel could not start.") + hint
      return strings.t("tunnel.failed", "The tunnel could not start: %1").arg(entry.message) + hint
    }
    if (entry.reason === "limit") return strings.t("tunnel.limit", "Too many tunnels are running (the limit is 64). Stop one first.")
    if (entry.reason === "timeout") return strings.t("tunnel.timeout", "The connection timed out.")
    if (entry.reason === "vanished") return strings.t("tunnel.vanished", "The tunnel closed right after it started.")
    if (entry.reason === "ambiguous") return strings.t("tunnel.ambiguous", "Several matching ssh processes were found, so none was tracked.")
    if (entry.reason === "no-forwards") return strings.t("tunnel.noForwards", "This host has no port forwards in your SSH config.")
    if (entry.reason === "ssh-missing") return strings.t("panel.sshMissing", "The ssh command was not found. Install openssh.")
    if (entry.reason === "stop") return strings.t("tunnel.stopFailed", "Could not stop the tunnel.")
    return strings.t("tunnel.error", "The tunnel command failed.")
  }

  /** Returns the busy or error message for the host under the cursor. */
  function statusText() {
    var host = root.page === "actions" ? root.actionHost : root.selected()
    var alias = host ? host.alias : ""
    if (root.tunnelBusyAction !== "" && (root.tunnelBusyAlias === alias || root.tunnelBusyAlias === ""))
      return root.tunnelBusyAction === "start" ? strings.t("tunnel.starting", "Starting the tunnel…") : strings.t("tunnel.stopping", "Stopping…")
    if (root.actionError !== "") return root.actionError
    var entry = root.tunnelErrors[root.aliasKey(alias)] || root.tunnelErrors[root.aliasKey("*")]
    return entry ? root.tunnelErrorText(entry) : ""
  }

  /** Builds the rows of the actions page for a host. */
  function actionsFor(host) {
    if (!host) return []
    var up = root.tunnelMap[root.aliasKey(host.alias)] === true
    var rows = [
      { id: "ssh", key: "", glyph: "󰆍", label: strings.t("action.ssh", "Open in terminal"), detail: "" },
      { id: "sftp", key: "s", glyph: "󰉋", label: strings.t("row.sftp", "Open SFTP"), detail: "" },
      { id: "tmux", key: "t", glyph: "󰆍", label: strings.t("action.tmux", "Open in tmux"), detail: "" },
      { id: "tunnel", key: "f", glyph: up ? "󰓛" : "󰐊", label: up ? strings.t("action.tunnelStop", "Stop tunnel") : strings.t("action.tunnelStart", "Start tunnel"), detail: "" }
    ]
    if (root.tools.wlCopy) {
      rows.push({ id: "copy", key: "y", glyph: "󰆏", label: strings.t("action.copy", "Copy ssh command"), detail: "" })
      if (host.target !== "")
        rows.push({ id: "copyTarget", key: "u", glyph: "󰆏", label: strings.t("action.copyTarget", "Copy user@host"), detail: host.target })
    }
    if (root.tools.sshCopyId)
      rows.push({ id: "copyId", key: "i", glyph: "󰌆", label: strings.t("action.copyId", "Install your key (ssh-copy-id)"), detail: "" })
    if (root.tools.code && root.configArgs.length === 0)
      rows.push({ id: "code", key: "v", glyph: "󰨞", label: strings.t("action.code", "Open in VS Code"), detail: "" })
    var ordinal = 0
    for (var i = 0; i < root.commands.length; i++) {
      var c = root.commands[i]
      if (c.hosts !== null && c.hosts.indexOf(host.alias) === -1) continue
      ordinal++
      rows.push({ id: "run", key: ordinal <= 9 ? String(ordinal) : "", glyph: "󰐊", label: c.name, detail: c.preview, arg: c.id })
    }
    rows.push({ id: "editCommands", key: "c", glyph: "󰏫", label: strings.t("action.editCommands", "Edit saved commands"), detail: "" })
    if (root.canEdit(host))
      rows.push({ id: "editHost", key: "m", glyph: "󰏫", label: strings.t("action.editHost", "Edit host"), detail: "" })
    if (root.canDelete(host))
      rows.push({ id: "deleteHost", key: "d", glyph: "󰆴", label: strings.t("action.deleteHost", "Delete host"), detail: "" })
    return rows
  }

  /** Returns the entry of the plugin file for a host, or null when the file does not define it. */
  function editorHost(alias) {
    var list = root.editor.hosts || []
    for (var i = 0; i < list.length; i++)
      if (list[i].alias === alias) return list[i]
    return null
  }

  /** Returns true when the form may change the host. */
  function canEdit(host) {
    return !!host && root.editorOn && host.editable === true && root.editorHost(host.alias) !== null
  }

  /** Returns true when the host can be removed from the plugin file. */
  function canDelete(host) {
    return !!host && root.editorOn && root.editor.file === "ok" && root.editorHost(host.alias) !== null
  }

  /** Returns the name of the file that holds the Include line, or a question mark. */
  function includeFile(where) {
    return where ? where.file : "?"
  }

  /** Returns the line number of the Include line as text, or a question mark. */
  function includeAt(where) {
    return where && where.line > 0 ? String(where.line) : "?"
  }

  /** Explains why the plugin file is left alone. */
  function unsafeReason(reason) {
    if (reason === "symlink") return strings.t("editor.reason.symlink", "it is a symbolic link")
    if (reason === "not-regular") return strings.t("editor.reason.notRegular", "it is not a regular file")
    if (reason === "owner") return strings.t("editor.reason.owner", "it belongs to another user")
    if (reason === "too-large") return strings.t("editor.reason.tooLarge", "it is too large")
    if (reason === "dir") return strings.t("editor.reason.dir", "~/.ssh is not a private folder owned by you")
    return strings.t("editor.reason.io", "it could not be read")
  }

  /** Returns the banner of the host list: its text, an extra line, whether it is urgent and whether it offers to open the plugin file. */
  function editorBanner() {
    var none = { text: "", extra: "", urgent: false, openFile: false }
    if (root.configArgs.length > 0)
      return { text: strings.t("editor.disabled", "Hosts can only be added here when the default SSH config is used."), extra: "", urgent: false, openFile: false }
    if (!root.loaded || !root.editorOn) return none
    var e = root.editor
    if (e.file === "foreign")
      return { text: strings.t("editor.foreign", "omassh.config was edited by hand, so the panel leaves it alone."), extra: "", urgent: false, openFile: true }
    if (e.file === "unsafe" && e.fileReason === "mode")
      return { text: strings.t("editor.unsafeMode", "ssh refuses omassh.config because other users can write to it. Run: chmod 600 ~/.ssh/omassh.config"), extra: "", urgent: true, openFile: false }
    if (e.file === "unsafe")
      return { text: strings.t("editor.unsafe", "The panel leaves omassh.config alone because %1.").arg(root.unsafeReason(e.fileReason)), extra: "", urgent: false, openFile: false }
    if (e.include === "active" && e.incomplete === true)
      return { text: strings.t("editor.incomplete", "Part of your SSH config could not be read (an Include was skipped or a size limit was reached), so the panel cannot tell which names are free. Adding and editing hosts is off."), extra: "", urgent: false, openFile: false }
    if (e.include === "late")
      return { text: strings.t("editor.late", "The Include line (%1, line %2) has other settings above it, which override the hosts added here. Press n to add it at the top.").arg(root.includeFile(e.where)).arg(root.includeAt(e.where)), extra: "", urgent: false, openFile: false }
    if (e.include === "scoped")
      return { text: strings.t("editor.scoped", "The Include line (%1, line %2) is inside a Host or Match block, so ssh reads it only for some hosts. Press n to add it at the top.").arg(root.includeFile(e.where)).arg(root.includeAt(e.where)), extra: "", urgent: false, openFile: false }
    if (e.include === "missing")
      return {
        text: strings.t("editor.setup", "Hosts you add are saved in omassh.config. ssh reads it once an Include line is added to ~/.ssh/config. Press n to set it up."),
        extra: e.count > 0 ? strings.tn("editor.waiting", e.count, "%1 hosts in omassh.config are waiting for the Include line").arg(Commons.I18n.formatNumber(e.count)) : "",
        urgent: false,
        openFile: false
      }
    return none
  }

  /** Returns the lines shown around the Include line of a preview, each with whether it is the inserted one. */
  function contextLines(preview) {
    var out = []
    if (!preview || preview.loaded !== true) return out
    for (var i = 0; i < preview.before.length; i++) out.push({ text: preview.before[i], mark: false })
    out.push({ text: preview.insert, mark: true })
    for (var j = 0; j < preview.after.length; j++) out.push({ text: preview.after[j], mark: false })
    return out
  }

  /** Explains why the main config cannot be changed safely. */
  function refusalText(preview) {
    var where = preview.path
    if (preview.refusal === "not-regular") return strings.t("setup.refused.notRegular", "%1 is not a regular file.").arg(where)
    if (preview.refusal === "owner") return strings.t("setup.refused.owner", "%1 belongs to another user.").arg(where)
    if (preview.refusal === "mode") return strings.t("setup.refused.mode", "Other users can write to %1, so ssh would refuse it.").arg(where)
    if (preview.refusal === "links") return strings.t("setup.refused.links", "%1 has other hard links, so it cannot be replaced safely.").arg(where)
    if (preview.refusal === "dir") return strings.t("setup.refused.dir", "The folder of %1 is not safe to write to.").arg(where)
    if (preview.refusal === "too-large") return strings.t("setup.refused.tooLarge", "%1 is larger than 1 MiB.").arg(where)
    if (preview.refusal === "bom") return strings.t("setup.refused.bom", "%1 starts with a byte order mark.").arg(where)
    if (preview.refusal === "group") return strings.t("setup.refused.group", "%1 belongs to a group you are not in, so a new file could not keep its group.").arg(where)
    if (preview.refusal === "acl") return strings.t("setup.refused.acl", "The access control list of %1 could not be kept.").arg(where)
    if (preview.refusal === "managed-foreign") return strings.t("setup.refused.managedForeign", "omassh.config was edited by hand, so ssh could refuse it. Fix or remove it first; adding the line now could break every host.")
    return strings.t("setup.refused.managedUnsafe", "omassh.config is not safe to use. Fix that first.")
  }

  /** Returns the action row of a host that is bound to a key, or null. */
  function rowForKey(host, key) {
    var rows = root.actionsFor(host)
    for (var i = 0; i < rows.length; i++)
      if (rows[i].key === key) return rows[i]
    return null
  }

  /** Reloads the host list. */
  function reload() {
    if (listProc.running) { root.listRefreshPending = true; return }
    listProc.running = true
  }

  /** Starts the reachability check. */
  function probe() {
    if (probeProc.running) return
    root.probing = true
    probeProc.running = true
  }

  /** Reloads the running tunnels, once more if a reload was already under way. */
  function loadTunnels() {
    if (tunnelListProc.running) { root.tunnelRefreshPending = true; return }
    tunnelListProc.running = true
  }

  /** Asks every bar instance to reload the running tunnels. */
  function broadcastTunnels() {
    if (root.hostWidget && typeof root.hostWidget.broadcast === "function") root.hostWidget.broadcast("refreshTunnels")
    else root.loadTunnels()
  }

  /** Returns the tunnel errors without the entries of the given aliases. */
  function errorsWithout(first, second) {
    var out = {}
    for (var key in root.tunnelErrors)
      if (key !== root.aliasKey(first) && key !== root.aliasKey(second)) out[key] = root.tunnelErrors[key]
    return out
  }

  /** Returns a key hint without the entries that name one of the missing keys. */
  function keyHint(text, missing) {
    var parts = text.split(" · ")
    var out = []
    for (var i = 0; i < parts.length; i++)
      if (missing.indexOf(parts[i].split(" ")[0]) === -1) out.push(parts[i])
    return out.join(" · ")
  }

  /** Returns the key hint of the actions page, leaving out the keys whose rows are hidden. */
  function actionHint() {
    var present = []
    for (var i = 0; i < root.actionRows.length; i++) present.push(root.actionRows[i].key)
    var gates = [["y", "y"], ["u", "u"], ["i", "i"], ["v", "v"], ["m", "m"], ["d", "d"], ["1-9", "1"]]
    var missing = []
    for (var j = 0; j < gates.length; j++)
      if (present.indexOf(gates[j][1]) === -1) missing.push(gates[j][0])
    return root.keyHint(strings.t("actions.keys", "↵ run · s sftp · t tmux · f tunnel · y copy · u user@host · i ssh-copy-id · v VS Code · c commands · m modify · d delete · 1-9 saved · x stop · ← back"), missing)
  }

  /** Returns the key hint of the host list, leaving out the keys that do nothing for the selected host. */
  function hostHint() {
    var host = root.selected()
    var missing = []
    if (!root.tools.wlCopy) missing.push("y")
    if (!root.editorOn) missing.push("n")
    if (!root.canEdit(host)) missing.push("m")
    if (!root.canDelete(host)) missing.push("d")
    return root.keyHint(strings.t("panel.keys", "↵ open · s sftp · t tmux · f tunnel · y copy · a more · x stop · p pin · n new · m modify · d delete · r check · e edit · / find"), missing)
  }

  /** Runs one tunnel command and clears the errors it replaces. */
  function runTunnel(action, alias, argv) {
    if (tunnelProc.running || root.tunnelBusyAction !== "") return
    root.tunnelErrors = root.errorsWithout(alias, "*")
    root.tunnelBusyAction = action
    root.tunnelBusyAlias = alias
    tunnelProc.command = argv
    tunnelProc.running = true
  }

  /** Applies the result of a tunnel command and refreshes every bar instance. */
  function finishTunnel(exitCode, text) {
    var action = root.tunnelBusyAction
    var alias = action === "all" ? "*" : root.tunnelBusyAlias
    root.tunnelBusyAction = ""
    root.tunnelBusyAlias = ""
    var data = null
    var output = String(text || "")
    if (output.length < 100000) {
      try { data = JSON.parse(output) } catch (e) { data = null }
    }
    var ok = exitCode === 0 && data !== null && typeof data === "object"
      && (action === "start" ? data.state === "up" : action === "stop" ? data.state === "down" : Array.isArray(data.stopped))
    if (!ok) {
      var errors = root.errorsWithout(alias, alias)
      var reason = action !== "start" ? "stop"
        : (data && data.state === "down" && typeof data.reason === "string") ? str(data.reason, 20) : "error"
      errors[root.aliasKey(alias)] = { reason: reason, message: data ? str(data.message, 200) : "" }
      root.tunnelErrors = errors
    }
    root.broadcastTunnels()
  }

  /** Ends a tunnel command whose process went away without reporting an exit. */
  function settleTunnel() {
    if (root.tunnelBusyAction !== "" && !tunnelProc.running) root.finishTunnel(-1, "")
  }

  /** Starts the tunnel of a host. */
  function startTunnel(host) {
    if (!host) return
    root.runTunnel("start", host.alias, [root.cli, "tunnel", "start"].concat(root.configArgs).concat(["--", host.alias]))
  }

  /** Stops the tunnel of a host when one is up. */
  function stopTunnel(host) {
    if (!host || root.tunnelMap[root.aliasKey(host.alias)] !== true) return
    root.runTunnel("stop", host.alias, [root.cli, "tunnel", "stop"].concat(root.configArgs).concat(["--", host.alias]))
  }

  /** Stops every tunnel. */
  function stopAllTunnels() {
    if (root.activeTunnels === 0) return
    root.runTunnel("all", "", [root.cli, "tunnel", "stop", "--all"].concat(root.configArgs))
  }

  /** Stops the tunnel of a host when it is up, otherwise starts it. */
  function toggleTunnel(host) {
    if (host && root.tunnelMap[root.aliasKey(host.alias)] === true) root.stopTunnel(host)
    else root.startTunnel(host)
  }

  /** Opens a terminal for a host with the given connect flags and closes the panel. */
  function connect(host, flags) {
    if (!host) return
    var argv = [root.cli, "connect"].concat(root.configArgs).concat(flags)
    argv.push("--", host.alias)
    Quickshell.execDetached(argv)
    root.close()
  }

  /** Copies the ssh command, or user@host, of a host to the clipboard and closes the panel. */
  function copyHost(host, target) {
    if (!host) return
    var argv = [root.cli, "copy"].concat(root.configArgs)
    if (target) argv.push("--target")
    argv.push("--", host.alias)
    Quickshell.execDetached(argv)
    root.close()
  }

  /** Opens a host in a VS Code remote window and closes the panel. */
  function openCode(host) {
    if (!host) return
    Quickshell.execDetached([root.cli, "code", "--", host.alias])
    root.close()
  }

  /** Toggles the pin of a host. */
  function togglePin(host) {
    if (!host || mutateProc.running) return
    root.pendingAlias = host.alias
    mutateProc.command = [root.cli, host.pinned ? "unpin" : "pin"].concat(host.pinned ? [] : root.configArgs).concat(["--", host.alias])
    mutateProc.running = true
  }

  /** Opens a file in the editor and closes the panel. */
  function openInEditor(path) {
    if (path.charAt(0) !== "/" || path.indexOf("\n") !== -1) return
    Quickshell.execDetached(["omarchy", "launch", "editor", path])
    root.close()
  }

  /** Edits the SSH config. */
  function editConfig() {
    root.openInEditor(root.configPath !== "" ? root.configPath : Quickshell.env("HOME") + "/.ssh/config")
  }

  /** Creates the saved commands file when needed and opens it in the editor; the panel closes when that worked. */
  function editCommands() {
    if (root.editPending) return
    root.actionError = ""
    root.editPending = true
    commandsEditProc.running = true
  }

  /** Closes the panel when the editor was opened, otherwise shows why it was not. */
  function finishEdit(exitCode, text) {
    root.editPending = false
    if (exitCode === 0) { root.close(); return }
    var message = str(String(text || "").trim(), 300)
    root.actionError = message !== "" ? message : strings.t("commands.editFailed", "Could not open the saved commands file.")
  }

  /** Ends an edit whose process went away without reporting an exit. */
  function settleEdit() {
    if (root.editPending && !commandsEditProc.running) root.finishEdit(-1, "")
  }

  /** Runs an action row on a host. */
  function runAction(host, row) {
    if (!host || !row) return
    if (row.id === "ssh") root.connect(host, [])
    else if (row.id === "sftp") root.connect(host, ["--sftp"])
    else if (row.id === "tmux") root.connect(host, ["--tmux"])
    else if (row.id === "tunnel") root.toggleTunnel(host)
    else if (row.id === "copy") root.copyHost(host, false)
    else if (row.id === "copyTarget") root.copyHost(host, true)
    else if (row.id === "copyId") root.connect(host, ["--copy-id"])
    else if (row.id === "code") root.openCode(host)
    else if (row.id === "run") root.connect(host, ["--run", row.arg])
    else if (row.id === "editCommands") root.editCommands()
    else if (row.id === "editHost") root.editHost(host)
    else if (row.id === "deleteHost") root.askDelete(host)
  }

  /** Runs the action bound to a typed key. */
  function pressKey(text) {
    if (root.page !== "hosts" && root.page !== "actions") return
    root.notice = ""
    root.editorError = ""
    var key = text.toLowerCase()
    var actions = root.page === "actions"
    var host = actions ? root.actionHost : root.selected()
    if (key === "p") root.togglePin(host)
    else if (key === "r") root.probe()
    else if (key === "e") root.editConfig()
    else if (!actions && key === "/") search.forceActiveFocus()
    else if (!actions && key === "a") root.openActions(host)
    else if (!actions && key === "n") root.newHost()
    else if (key === "m") root.editHost(host)
    else if (key === "d") root.askDelete(host)
    else if (actions || "stfy".indexOf(key) !== -1) root.runAction(host, root.rowForKey(host, key))
  }

  /** Shows the actions page of a host. */
  function openActions(host) {
    if (!host) return
    root.notice = ""
    root.editorError = ""
    root.actionAlias = host.alias
    root.actionCursor = 0
    root.page = "actions"
    keyCatcher.forceActiveFocus()
  }

  /** Goes back one page, or closes the panel from the host list. */
  function goBack() {
    if (root.page === "actions") root.closeActions()
    else if (root.page === "edit") root.cancelForm()
    else if (root.page === "setup") root.closeSetup()
    else root.close()
  }

  /** Opens the form for a new host, or the Include setup first when ssh does not read the plugin file first. */
  function newHost() {
    if (!root.editorOn || root.editorBusy) return
    root.notice = ""
    root.editorError = ""
    if (root.editor.file === "foreign" || root.editor.file === "unsafe") return
    if (root.editor.include !== "active") root.openSetup()
    else if (root.editor.incomplete !== true) root.openForm(null)
  }

  /** Opens the form for a host of the plugin file. */
  function editHost(host) {
    if (!root.canEdit(host) || root.editorBusy) return
    root.notice = ""
    root.editorError = ""
    root.openForm(root.editorHost(host.alias))
  }

  /** Shows the form, filled from a host of the plugin file or empty for a new host. */
  function openForm(entry) {
    root.formMode = entry ? "edit" : "new"
    root.formOriginal = entry ? entry.alias : ""
    root.formExpect = entry ? entry.expect : ""
    root.fieldErrors = []
    root.formError = ""
    root.page = "edit"
    form.load(entry)
    form.focusField(0)
  }

  /** Leaves the form for the host list. */
  function leaveForm() {
    root.fieldErrors = []
    root.formError = ""
    root.page = "hosts"
    keyCatcher.forceActiveFocus()
    hostList.positionViewAtIndex(root.cursor, ListView.Contain)
  }

  /** Closes the form without saving, unless a save is under way. */
  function cancelForm() {
    if (root.savePending) return
    root.leaveForm()
  }

  /** Sends the form to `omassh host save`; the CLI is the only validator. */
  function saveHost() {
    if (root.editorBusy || hostSaveProc.running) return
    root.fieldErrors = []
    root.formError = ""
    hostSaveProc.payload = JSON.stringify({ version: 1, original: root.formOriginal, expect: root.formExpect, host: form.values() })
    root.savePending = true
    hostSaveProc.running = true
  }

  /** Explains why a host could not be saved. */
  function saveErrorText(data) {
    var reason = root.replyReason(data)
    var message = root.replyMessage(data)
    if (reason === "conflict") return strings.t("save.conflict", "This host changed on disk. Close the form and open it again.")
    if (reason === "incomplete") return strings.t("save.incomplete", "Part of your SSH config could not be read, so the panel cannot tell whether this name is free. Nothing was saved.")
    if (reason === "not-included") return strings.t("save.notIncluded", "ssh does not read omassh.config first yet. Close the form and add the Include line.")
    if (reason === "ssh-rejected") return strings.t("save.sshRejected", "ssh rejected these values: %1").arg(message)
    if (reason === "tunnel-up") return strings.t("save.tunnelUp", "Stop the tunnel of %1 before renaming the host.").arg(root.formOriginal)
    if (reason === "not-managed") return strings.t("save.notManaged", "This host is not stored in omassh.config, so it cannot be changed here.")
    if (reason === "ssh-missing") return strings.t("panel.sshMissing", "The ssh command was not found. Install openssh.")
    return strings.t("save.failed", "Could not save the host. %1").arg(message).trim()
  }

  /** Applies the result of `omassh host save`. */
  function finishSave(exitCode, text) {
    hostSaveProc.payload = ""
    if (!root.savePending) return
    root.savePending = false
    var data = root.parseReply(text)
    if (exitCode === 0 && data && data.ok === true) {
      var alias = str(data.alias, 128)
      root.notice = data.tunnelUp === true
        ? strings.t("save.tunnelRestart", "Saved %1. Restart its tunnel to use the new forwards.").arg(alias)
        : strings.t("save.done", "Saved %1.").arg(alias)
      root.pendingAlias = alias
      root.leaveForm()
      root.reload()
      root.broadcastTunnels()
      return
    }
    var problems = (data && data.reason === "invalid") ? root.parseFieldErrors(data.errors) : []
    if (problems.length > 0) {
      root.fieldErrors = problems
      form.focusFirstError()
      return
    }
    root.formError = root.saveErrorText(data)
    root.reload()
  }

  /** Drops the error of a removed forward row and moves the errors of the rows after it up by one. */
  function dropRowError(row) {
    var out = []
    for (var i = 0; i < root.fieldErrors.length; i++) {
      var e = root.fieldErrors[i]
      if (e.field !== "forwards" || e.index < 0) out.push(e)
      else if (e.index !== row) out.push({ field: e.field, index: e.index > row ? e.index - 1 : e.index, code: e.code })
    }
    root.fieldErrors = out
  }

  /** Ends a save whose process went away without reporting an exit. */
  function settleSave() {
    if (root.savePending && !hostSaveProc.running) root.finishSave(-1, "")
  }

  /** Asks for confirmation before a host is removed from the plugin file. */
  function askDelete(host) {
    if (!root.canDelete(host) || root.editorBusy || root.deleteConfirmOpen) return
    var entry = root.editorHost(host.alias)
    root.notice = ""
    root.editorError = ""
    root.deleteAlias = entry.alias
    root.deleteExpect = entry.expect
    root.deleteTunnel = host.origin === "managed" && root.editor.incomplete !== true && root.tunnelMap[root.aliasKey(host.alias)] === true
    deleteConfirm.selectedIndex = 0
    root.deleteConfirmOpen = true
    confirmKeys.forceActiveFocus()
  }

  /** Closes the delete confirmation. */
  function cancelDelete() {
    root.deleteConfirmOpen = false
    keyCatcher.forceActiveFocus()
  }

  /** Removes the confirmed host from the plugin file. */
  function confirmDelete() {
    var alias = root.deleteAlias
    var expect = root.deleteExpect
    root.cancelDelete()
    if (alias === "" || !/^[0-9a-f]{16}$/.test(expect) || root.editorBusy || hostDeleteProc.running) return
    root.deletePending = true
    hostDeleteProc.command = [root.cli, "host", "delete", "--expect", expect, "--", alias]
    hostDeleteProc.running = true
  }

  /** Applies the result of `omassh host delete`. */
  function finishDelete(exitCode, text) {
    if (!root.deletePending) return
    root.deletePending = false
    var data = root.parseReply(text)
    if (exitCode === 0 && data && data.ok === true) {
      root.notice = strings.t("delete.done", "Deleted %1.").arg(root.deleteAlias)
      if (root.page === "actions") root.closeActions()
      root.broadcastTunnels()
    } else {
      root.editorError = strings.t("delete.failed", "Could not delete the host. %1").arg(root.replyMessage(data)).trim()
    }
    root.reload()
  }

  /** Ends a delete whose process went away without reporting an exit. */
  function settleDelete() {
    if (root.deletePending && !hostDeleteProc.running) root.finishDelete(-1, "")
  }

  /** Shows the page that adds the Include line to the main config. */
  function openSetup() {
    root.setup = root.emptySetup()
    root.setupError = ""
    root.page = "setup"
    keyCatcher.forceActiveFocus()
    root.loadSetup()
  }

  /** Leaves the Include setup unless the line is being added. */
  function closeSetup() {
    if (root.includeMode === "apply") return
    root.setupError = ""
    root.page = "hosts"
    keyCatcher.forceActiveFocus()
  }

  /** Loads the Include preview. */
  function loadSetup() {
    if (root.includeMode !== "" || includeProc.running) return
    root.includeMode = "status"
    includeProc.command = [root.cli, "include", "status"]
    includeProc.running = true
  }

  /** Adds the Include line the preview showed to the main config. */
  function applyInclude() {
    var expect = root.setup.expect
    if (root.page !== "setup" || root.editorBusy || includeProc.running || root.setup.loaded !== true || root.setup.refusal !== "") return
    if (typeof expect !== "string" || !/^[0-9a-f]{16}$/.test(expect)) return
    root.setupError = ""
    root.includeMode = "apply"
    includeProc.command = [root.cli, "include", "apply", "--confirm", "--expect", expect]
    includeProc.running = true
  }

  /** Applies the result of `omassh include status` or `omassh include apply`. */
  function finishInclude(exitCode, text) {
    var mode = root.includeMode
    root.includeMode = ""
    var data = root.parseReply(text)
    if (mode === "status") {
      var preview = (exitCode === 0 && data) ? root.parseSetup(data) : null
      if (preview) root.setup = preview
      else root.setupError = strings.t("setup.failed", "Could not change the file. %1").arg(root.replyMessage(data)).trim()
    } else if (mode === "apply") {
      if (exitCode === 0 && data && data.ok === true && data.include === "active") {
        var path = root.setup.path
        root.notice = data.changed !== true ? strings.t("setup.unchanged", "ssh already reads omassh.config first.")
          : (typeof data.backup === "string" && data.backup !== "") ? strings.t("setup.changed", "Added the line to %1. Your old file is saved as %2.").arg(path).arg(str(data.backup, 1024))
          : strings.t("setup.created", "Created %1 with the Include line.").arg(path)
        root.reload()
        root.openForm(null)
      } else {
        root.setupError = strings.t("setup.failed", "Could not change the file. %1").arg(root.replyMessage(data)).trim()
        Qt.callLater(root.loadSetup)
      }
    }
  }

  /** Ends an Include command whose process went away without reporting an exit. */
  function settleInclude() {
    if (root.includeMode !== "" && !includeProc.running) root.finishInclude(-1, "")
  }

  /** Ends every pending editor command whose process is gone, and stops one that has run for a minute. */
  function settlePending() {
    root.pendingTicks++
    if (root.pendingTicks >= 12) {
      if (root.savePending) hostSaveProc.running = false
      if (root.deletePending) hostDeleteProc.running = false
      if (root.includeMode !== "") includeProc.running = false
    }
    root.settleSave()
    root.settleDelete()
    root.settleInclude()
  }

  /** Goes back from the actions page to the host list. */
  function closeActions() {
    root.actionError = ""
    root.page = "hosts"
    keyCatcher.forceActiveFocus()
    hostList.positionViewAtIndex(root.cursor, ListView.Contain)
  }

  /** Returns the host under the cursor, or null. */
  function selected() {
    return root.shown.length > 0 ? root.shown[Math.max(0, Math.min(root.cursor, root.shown.length - 1))] : null
  }

  /** Keeps the host cursor inside the list. */
  function clampCursor() {
    root.cursor = Math.max(0, Math.min(root.cursor, root.shown.length - 1))
  }

  /** Moves the host cursor by delta rows. */
  function moveCursor(delta) {
    if (root.shown.length === 0) return
    root.cursor = Math.max(0, Math.min(root.cursor + delta, root.shown.length - 1))
    hostList.positionViewAtIndex(root.cursor, ListView.Contain)
  }

  /** Moves the cursor of the actions page by delta rows. */
  function moveAction(delta) {
    if (root.actionRows.length === 0) return
    root.actionCursor = Math.max(0, Math.min(root.actionCursor + delta, root.actionRows.length - 1))
    actionList.positionViewAtIndex(root.actionCursor, ListView.Contain)
  }

  Process {
    id: listProc
    command: [root.cli, "list"].concat(root.configArgs)
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.applyList(text)
    }
    onExited: function(exitCode) {
      if (exitCode !== 0) root.loadFailed = true
      if (root.listRefreshPending) {
        root.listRefreshPending = false
        Qt.callLater(root.reload)
      }
    }
  }

  Process {
    id: probeProc
    command: [root.cli, "probe"].concat(root.configArgs)
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.applyProbe(text)
    }
    onExited: root.probing = false
  }

  Process {
    id: mutateProc
    onExited: root.reload()
  }

  Process {
    id: tunnelProc
    stdout: StdioCollector { id: tunnelOut; waitForEnd: true }
    onExited: function(exitCode) { root.finishTunnel(exitCode, tunnelOut.text) }
    onRunningChanged: if (!running) Qt.callLater(root.settleTunnel)
  }

  Process {
    id: commandsEditProc
    command: [root.cli, "commands", "edit"]
    stderr: StdioCollector { id: commandsEditErr; waitForEnd: true }
    onExited: function(exitCode) { root.finishEdit(exitCode, commandsEditErr.text) }
    onRunningChanged: if (!running) Qt.callLater(root.settleEdit)
  }

  Process {
    id: hostSaveProc
    property string payload: ""
    command: [root.cli, "host", "save"]
    stdinEnabled: true
    stdout: StdioCollector { id: hostSaveOut; waitForEnd: true }
    onStarted: {
      write(payload + "\n")
      payload = ""
    }
    onExited: function(exitCode) { root.finishSave(exitCode, hostSaveOut.text) }
    onRunningChanged: if (!running) Qt.callLater(root.settleSave)
  }

  Process {
    id: hostDeleteProc
    stdout: StdioCollector { id: hostDeleteOut; waitForEnd: true }
    onExited: function(exitCode) { root.finishDelete(exitCode, hostDeleteOut.text) }
    onRunningChanged: if (!running) Qt.callLater(root.settleDelete)
  }

  Process {
    id: includeProc
    stdout: StdioCollector { id: includeOut; waitForEnd: true }
    onExited: function(exitCode) { root.finishInclude(exitCode, includeOut.text) }
    onRunningChanged: if (!running) Qt.callLater(root.settleInclude)
  }

  Timer {
    id: pendingGuard
    interval: 5000
    repeat: true
    running: root.savePending || root.deletePending || root.includeMode !== ""
    onTriggered: root.settlePending()
    onRunningChanged: if (!running) root.pendingTicks = 0
  }

  Process {
    id: tunnelListProc
    command: [root.cli, "tunnel", "list"].concat(root.configArgs)
    stdout: StdioCollector { id: tunnelListOut; waitForEnd: true }
    onExited: function(exitCode) {
      if (exitCode === 0) root.applyTunnels(tunnelListOut.text)
      if (root.tunnelRefreshPending) {
        root.tunnelRefreshPending = false
        Qt.callLater(root.loadTunnels)
      }
    }
  }

  Component.onCompleted: root.loadTunnels()

  onOpenedChanged: {
    if (opened) {
      root.actionError = ""
      root.notice = ""
      root.editorError = ""
      root.cursor = 0
      root.reload()
      root.loadTunnels()
      if (root.autoProbe) root.probe()
    } else {
      search.text = ""
      root.page = "hosts"
      root.fieldErrors = []
      root.formError = ""
      root.setupError = ""
      root.deleteConfirmOpen = false
    }
  }
  onShownChanged: root.clampCursor()
  onHostsChanged: if (root.hosts.length === 0 && search.text !== "") search.text = ""
  onActionHostChanged: if (root.page === "actions" && !root.actionHost) root.closeActions()
  onActionRowsChanged: root.actionCursor = Math.max(0, Math.min(root.actionCursor, root.actionRows.length - 1))

  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem
    owner: root.barIdentity
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(360))
    contentHeight: panel.fittedContentHeight(Math.max(column.implicitHeight, root.deleteConfirmOpen ? Style.space(190) : 0), Style.space(560))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      blocked: search.activeFocus || form.activeFocus || confirmKeys.activeFocus || root.deleteConfirmOpen
      onMoveRequested: function(dx, dy) {
        if (root.page === "actions") {
          if (dy !== 0) root.moveAction(dy)
          else if (dx < 0) root.closeActions()
        } else if (root.page === "hosts") {
          if (dy !== 0) root.moveCursor(dy)
          else if (dx > 0) root.openActions(root.selected())
        }
      }
      onActivateRequested: {
        if (root.deleteConfirmOpen) return
        if (root.page === "actions") root.runAction(root.actionHost, root.actionRows[root.actionCursor])
        else if (root.page === "edit") form.focusField(0)
        else if (root.page === "hosts") root.connect(root.selected(), [])
      }
      onReturnRequested: if (root.page === "setup") root.applyInclude()
      onCloseRequested: root.goBack()
      onDeleteRequested: if (root.page === "actions" || root.page === "hosts") root.stopTunnel(root.page === "actions" ? root.actionHost : root.selected())
      onTabRequested: function(direction) {
        if (root.page === "edit") form.focusField(direction > 0 ? 0 : -1)
        else root.switchPanel(direction)
      }
      onTextKey: function(t, modifiers) {
        if (modifiers & (Qt.ControlModifier | Qt.AltModifier | Qt.MetaModifier)) return
        root.pressKey(t)
      }

      Column {
        id: column
        width: parent.width
        spacing: Style.space(8)

        Item {
          width: parent.width
          height: Style.space(28)

          Row {
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            spacing: Style.space(8)

            PanelActionButton {
              visible: root.page !== "hosts"
              anchors.verticalCenter: parent.verticalCenter
              iconText: "󰅁"
              tooltipText: strings.t("actions.back", "Back to the host list")
              foreground: root.fg
              fontFamily: root.fontFamily
              onClicked: root.goBack()
            }

            Text {
              visible: root.page === "edit"
              anchors.verticalCenter: parent.verticalCenter
              width: Math.min(implicitWidth, Style.space(240))
              text: root.formMode === "edit" ? strings.t("editor.edit", "Edit host") : strings.t("editor.new", "New host")
              textFormat: Text.PlainText
              color: Commons.Color.accent
              elide: Text.ElideRight
              font.family: root.fontFamily
              font.pixelSize: Style.font.subtitle
              font.bold: true
            }

            Text {
              visible: root.page === "setup"
              anchors.verticalCenter: parent.verticalCenter
              width: Math.min(implicitWidth, Style.space(240))
              text: strings.t("setup.title", "Add the Include line")
              textFormat: Text.PlainText
              color: Commons.Color.accent
              elide: Text.ElideRight
              font.family: root.fontFamily
              font.pixelSize: Style.font.subtitle
              font.bold: true
            }

            Text {
              visible: root.page === "actions"
              anchors.verticalCenter: parent.verticalCenter
              width: Math.min(implicitWidth, Style.space(240))
              text: root.actionAlias
              textFormat: Text.PlainText
              color: Commons.Color.accent
              elide: Text.ElideRight
              font.family: root.fontFamily
              font.pixelSize: Style.font.subtitle
              font.bold: true
            }

            Text {
              visible: root.page === "hosts"
              anchors.verticalCenter: parent.verticalCenter
              text: strings.t("panel.title", "SSH")
              textFormat: Text.PlainText
              color: Commons.Color.accent
              font.family: root.fontFamily
              font.pixelSize: Style.font.subtitle
              font.bold: true
              font.letterSpacing: 2
            }

            Text {
              visible: root.page === "hosts" && root.loaded && root.hosts.length > 0
              anchors.verticalCenter: parent.verticalCenter
              text: strings.tn("panel.count", root.hosts.length, "%1 hosts")
                .arg(Commons.I18n.formatNumber(root.hosts.length))
              textFormat: Text.PlainText
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }

            Text {
              visible: root.page === "hosts" && root.activeTunnels > 0
              anchors.verticalCenter: parent.verticalCenter
              text: strings.tn("panel.tunnels", root.activeTunnels, "%1 tunnels up")
                .arg(Commons.I18n.formatNumber(root.activeTunnels))
              textFormat: Text.PlainText
              color: Commons.Color.accent
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }
          }

          Row {
            visible: root.page === "hosts"
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            spacing: Style.space(4)

            Text {
              visible: root.probing
              anchors.verticalCenter: parent.verticalCenter
              text: strings.t("panel.checking", "Checking…")
              textFormat: Text.PlainText
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }

            PanelActionButton {
              visible: root.activeTunnels > 0
              iconText: "󰓛"
              tooltipText: strings.t("panel.stopAll", "Stop all tunnels")
              foreground: root.fg
              fontFamily: root.fontFamily
              enabled: root.tunnelBusyAction === ""
              onClicked: root.stopAllTunnels()
            }

            PanelActionButton {
              iconText: "󰑐"
              tooltipText: strings.t("panel.check", "Check which hosts are reachable")
              foreground: root.fg
              fontFamily: root.fontFamily
              enabled: !root.probing && root.hosts.length > 0
              onClicked: root.probe()
            }

            PanelActionButton {
              visible: root.editorOn
              iconText: "󰐕"
              tooltipText: strings.t("panel.addHost", "Add a host")
              foreground: root.fg
              fontFamily: root.fontFamily
              enabled: !root.editorBusy
              onClicked: root.newHost()
            }

            PanelActionButton {
              iconText: "󰏫"
              tooltipText: strings.t("panel.edit", "Edit SSH config")
              foreground: root.fg
              fontFamily: root.fontFamily
              onClicked: root.editConfig()
            }
          }
        }

        Column {
          id: hostsPage
          visible: root.page === "hosts"
          width: parent.width
          spacing: Style.space(8)

          Column {
            visible: root.banner.text !== ""
            width: parent.width
            spacing: Style.space(4)

            Text {
              width: parent.width
              text: root.banner.text
              textFormat: Text.PlainText
              color: root.banner.urgent ? Commons.Color.urgent : root.dim
              wrapMode: Text.WordWrap
              maximumLineCount: 6
              elide: Text.ElideRight
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }

            Text {
              visible: root.banner.extra !== ""
              width: parent.width
              text: root.banner.extra
              textFormat: Text.PlainText
              color: root.dim
              wrapMode: Text.WordWrap
              maximumLineCount: 2
              elide: Text.ElideRight
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }

            Button {
              visible: root.banner.openFile
              text: strings.t("editor.openFile", "Open omassh.config")
              foreground: root.fg
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              bordered: true
              onClicked: root.openInEditor(root.editor.path)
            }
          }

          TextField {
            id: search
            visible: root.hosts.length > 0
            width: parent.width
            foreground: root.fg
            placeholderText: strings.t("panel.search", "Search hosts")
            onTextChanged: { root.query = text; root.cursor = 0; hostList.positionViewAtBeginning() }
            onAccepted: { root.connect(root.selected(), []) }
            Keys.onPressed: function(event) {
              if (event.key === Qt.Key_Down) {
                keyCatcher.forceActiveFocus()
                root.cursor = 0
                event.accepted = true
              } else if (event.key === Qt.Key_Up) {
                keyCatcher.forceActiveFocus()
                event.accepted = true
              } else if (event.key === Qt.Key_Escape) {
                if (search.text !== "") search.text = ""
                else keyCatcher.forceActiveFocus()
                event.accepted = true
              }
            }
          }

          PanelSeparator { foreground: root.fg }

          ListView {
            id: hostList
            visible: root.shown.length > 0
            width: parent.width
            height: Math.min(contentHeight, Style.space(320))
            clip: true
            spacing: Style.space(4)
            model: root.shown
            reuseItems: true
            boundsBehavior: Flickable.StopAtBounds
            interactive: contentHeight > height
            ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

            delegate: HostRow {
              required property var modelData
              required property int index
              width: hostList.width
              host: modelData
              rowIndex: index
            }
          }

          Text {
            visible: root.loadFailed
            width: parent.width
            text: strings.t("panel.loadError", "Could not read your SSH config.")
            textFormat: Text.PlainText
            color: Commons.Color.urgent
            wrapMode: Text.WordWrap
            font.family: root.fontFamily
            font.pixelSize: Style.font.body
          }

          Text {
            visible: root.loaded && !root.loadFailed && !root.sshFound
            width: parent.width
            text: strings.t("panel.sshMissing", "The ssh command was not found. Install openssh.")
            textFormat: Text.PlainText
            color: Commons.Color.urgent
            wrapMode: Text.WordWrap
            font.family: root.fontFamily
            font.pixelSize: Style.font.body
          }

          Text {
            visible: root.loaded && root.hosts.length > 0 && root.shown.length === 0
            width: parent.width
            text: strings.t("panel.noMatches", "No matching hosts")
            textFormat: Text.PlainText
            color: root.dim
            horizontalAlignment: Text.AlignHCenter
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
          }

          Column {
            visible: root.loaded && !root.loadFailed && root.hosts.length === 0
            width: parent.width
            spacing: Style.space(8)

            Text {
              width: parent.width
              text: strings.t("panel.empty", "No hosts in your SSH config yet.")
              textFormat: Text.PlainText
              color: root.fg
              wrapMode: Text.WordWrap
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }

            Text {
              width: parent.width
              text: strings.t("panel.emptyHint", "Add a block like this to %1 and it shows up here:")
                .arg(root.configPath !== "" ? root.configPath : "~/.ssh/config")
              textFormat: Text.PlainText
              color: root.dim
              wrapMode: Text.Wrap
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
            }

            Text {
              width: parent.width
              text: "Host server\n    HostName server.example.com\n    User admin"
              textFormat: Text.PlainText
              color: Commons.Color.accent
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
            }
          }

          Text {
            visible: root.skipped > 0
            width: parent.width
            text: strings.tn("panel.skipped", root.skipped, "%1 hosts skipped").arg(Commons.I18n.formatNumber(root.skipped))
            textFormat: Text.PlainText
            color: root.dim
            wrapMode: Text.WordWrap
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }

          Text {
            visible: root.errors.length > 0
            width: parent.width
            text: strings.t("panel.errors", "Some config files could not be read: %1").arg(root.errors.join(", "))
            textFormat: Text.PlainText
            color: root.dim
            wrapMode: Text.WordWrap
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }
        }

        Column {
          id: actionsPage
          visible: root.page === "actions" && root.actionHost !== null
          width: parent.width
          spacing: Style.space(8)

          Text {
            width: parent.width
            text: root.actionHost ? root.detailFor(root.actionHost) : ""
            textFormat: Text.PlainText
            color: root.dim
            elide: Text.ElideRight
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }

          Text {
            width: parent.width
            text: root.actionHost && root.actionHost.forwards.length > 0
              ? strings.t("actions.forwards", "Port forwards")
              : strings.t("actions.noForwards", "No port forwards in your SSH config")
            textFormat: Text.PlainText
            color: root.fg
            elide: Text.ElideRight
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            font.bold: true
          }

          ListView {
            id: forwardList
            visible: count > 0
            width: parent.width
            height: Math.min(contentHeight, Style.space(96))
            clip: true
            model: root.actionHost ? root.actionHost.forwards : []
            boundsBehavior: Flickable.StopAtBounds
            interactive: contentHeight > height

            delegate: Text {
              required property var modelData
              width: forwardList.width
              text: root.forwardText(modelData)
              textFormat: Text.PlainText
              color: root.dim
              elide: Text.ElideRight
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }
          }

          Text {
            visible: root.actionHost !== null && root.actionHost.forwardsMore > 0
            width: parent.width
            text: strings.tn("actions.forwardsMore", root.actionHost ? root.actionHost.forwardsMore : 0, "%1 more forwards not shown")
              .arg(Commons.I18n.formatNumber(root.actionHost ? root.actionHost.forwardsMore : 0))
            textFormat: Text.PlainText
            color: root.dim
            wrapMode: Text.WordWrap
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }

          Text {
            visible: root.actionHost !== null && root.actionHost.forwardsUncertain
            width: parent.width
            text: strings.t("actions.forwardsUncertain", "A Match block in your SSH config may add forwards that are not shown.")
            textFormat: Text.PlainText
            color: root.dim
            wrapMode: Text.WordWrap
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }

          PanelSeparator { foreground: root.fg }

          ListView {
            id: actionList
            width: parent.width
            height: Math.min(contentHeight, Style.space(220))
            clip: true
            spacing: Style.space(4)
            model: root.actionRows
            boundsBehavior: Flickable.StopAtBounds
            interactive: contentHeight > height
            ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

            delegate: ActionRow {
              required property var modelData
              required property int index
              width: actionList.width
              entry: modelData
              rowIndex: index
            }
          }

          Text {
            visible: root.commandsError !== ""
            width: parent.width
            text: root.commandsErrorText(root.commandsError)
            textFormat: Text.PlainText
            color: Commons.Color.urgent
            wrapMode: Text.Wrap
            maximumLineCount: 4
            elide: Text.ElideRight
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }

          Text {
            visible: root.commandsError === "" && root.commands.length === 0
            width: parent.width
            text: strings.t("commands.none", "No saved commands yet. Add them to %1").arg(root.commandsPath)
            textFormat: Text.PlainText
            color: root.dim
            wrapMode: Text.Wrap
            maximumLineCount: 3
            elide: Text.ElideRight
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }

          Text {
            visible: root.commandsSkipped > 0
            width: parent.width
            text: strings.tn("commands.skipped", root.commandsSkipped, "%1 saved commands skipped").arg(Commons.I18n.formatNumber(root.commandsSkipped))
            textFormat: Text.PlainText
            color: root.dim
            wrapMode: Text.WordWrap
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }
        }

        HostForm {
          id: form
          visible: root.page === "edit"
          width: parent.width
          strings: root.translations
          fg: root.fg
          dim: root.dim
          fontFamily: root.fontFamily
          errors: root.fieldErrors
          busy: root.savePending
          onSaveRequested: root.saveHost()
          onCancelRequested: root.cancelForm()
          onRowRemoved: function(row) { root.dropRowError(row) }
        }

        Text {
          visible: root.page === "edit" && root.formError !== ""
          width: parent.width
          text: root.formError
          textFormat: Text.PlainText
          color: Commons.Color.urgent
          wrapMode: Text.WordWrap
          maximumLineCount: 6
          elide: Text.ElideRight
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
        }

        Column {
          id: setupPage
          visible: root.page === "setup"
          width: parent.width
          spacing: Style.space(8)

          Text {
            visible: root.setup.loaded === true && (root.setup.include === "late" || root.setup.include === "scoped")
            width: parent.width
            text: root.setup.include === "scoped"
              ? strings.t("setup.scoped", "The Include line (%1, line %2) is inside a Host or Match block, so ssh reads it only for some hosts. Enter adds it at the top.").arg(root.includeFile(root.setup.where)).arg(root.includeAt(root.setup.where))
              : strings.t("setup.late", "The Include line (%1, line %2) has other settings above it, which override the hosts added here. Enter adds it at the top.").arg(root.includeFile(root.setup.where)).arg(root.includeAt(root.setup.where))
            textFormat: Text.PlainText
            color: root.fg
            wrapMode: Text.WordWrap
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
          }

          Text {
            visible: root.setup.loaded === true && root.setup.include !== "active" && root.setup.refusal === ""
            width: parent.width
            text: root.setup.create === true
              ? strings.t("setup.create", "%1 does not exist yet. It will be created with this line:").arg(root.setup.path)
              : strings.t("setup.explain", "ssh reads omassh.config only after ~/.ssh/config has an Include line for it. This adds one line at the top, above every setting:")
            textFormat: Text.PlainText
            color: root.fg
            wrapMode: Text.WordWrap
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
          }

          Text {
            visible: root.setup.loaded === true && root.setup.include !== "active" && root.setup.create !== true
            width: parent.width
            text: root.setup.target !== "" ? root.setup.path + " → " + root.setup.target : root.setup.path
            textFormat: Text.PlainText
            color: root.dim
            wrapMode: Text.WrapAnywhere
            maximumLineCount: 3
            elide: Text.ElideRight
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }

          Text {
            visible: root.setup.loaded === true && root.setup.include === "active"
            width: parent.width
            text: strings.t("setup.unchanged", "ssh already reads omassh.config first.")
            textFormat: Text.PlainText
            color: root.fg
            wrapMode: Text.WordWrap
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
          }

          Column {
            visible: root.setup.loaded === true && root.setup.include !== "active" && root.setup.refusal === ""
            width: parent.width
            spacing: Style.space(2)

            Repeater {
              model: root.setupLines

              delegate: Text {
                required property var modelData
                width: parent.width
                text: (modelData.mark ? "+ " : "  ") + modelData.text
                textFormat: Text.PlainText
                color: modelData.mark ? Commons.Color.accent : root.dim
                elide: Text.ElideRight
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                font.bold: modelData.mark
              }
            }
          }

          Text {
            visible: root.setup.loaded === true && root.setup.include !== "active" && root.setup.refusal === ""
            width: parent.width
            text: strings.t("setup.at", "Inserted as line %1").arg(Commons.I18n.formatNumber(root.setup.line))
            textFormat: Text.PlainText
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }

          Text {
            visible: root.setup.loaded === true && root.setup.include !== "active" && root.setup.refusal === "" && root.setup.create !== true
            width: parent.width
            text: strings.t("setup.backup", "A backup of the file is saved first. Close ~/.ssh/config in your editor before you continue.")
            textFormat: Text.PlainText
            color: root.dim
            wrapMode: Text.WordWrap
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }

          Text {
            visible: root.setup.loaded === true && root.setup.include !== "active" && root.setup.refusal === "" && root.setup.create !== true && root.setup.acl === true
            width: parent.width
            text: strings.t("setup.acl", "Its access control list (ACL) will be kept when the file is replaced.")
            textFormat: Text.PlainText
            color: root.dim
            wrapMode: Text.WordWrap
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }

          Text {
            visible: root.setup.loaded === true && root.setup.refusal !== ""
            width: parent.width
            text: root.setup.loaded === true && root.setup.refusal !== "" ? root.refusalText(root.setup) : ""
            textFormat: Text.PlainText
            color: Commons.Color.urgent
            wrapMode: Text.WordWrap
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
          }

          Text {
            visible: root.setup.loaded === true && root.setup.refusal !== "" && root.setup.refusal.indexOf("managed-") !== 0
            width: parent.width
            text: strings.t("setup.manual", "Add this line at the top of %1 yourself:").arg(root.setup.path)
            textFormat: Text.PlainText
            color: root.fg
            wrapMode: Text.WordWrap
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
          }

          Text {
            visible: root.setup.loaded === true && root.setup.refusal !== "" && root.setup.refusal.indexOf("managed-") !== 0
            width: parent.width
            text: root.setup.insert
            textFormat: Text.PlainText
            color: Commons.Color.accent
            elide: Text.ElideRight
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            font.bold: true
          }

          Text {
            visible: root.setupError !== ""
            width: parent.width
            text: root.setupError
            textFormat: Text.PlainText
            color: Commons.Color.urgent
            wrapMode: Text.WordWrap
            maximumLineCount: 8
            elide: Text.ElideRight
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }

          Text {
            visible: root.includeMode !== ""
            width: parent.width
            text: strings.t("editor.working", "Working…")
            textFormat: Text.PlainText
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }

          Button {
            visible: root.setup.loaded === true && root.setup.include !== "active" && root.setup.refusal === ""
            text: strings.t("setup.apply", "Add the line")
            foreground: root.fg
            fontFamily: root.fontFamily
            fontSize: Style.font.bodySmall
            bordered: true
            enabled: !root.editorBusy
            onClicked: root.applyInclude()
          }
        }

        Text {
          visible: root.notice !== "" && (root.page === "hosts" || root.page === "actions")
          width: parent.width
          text: root.notice
          textFormat: Text.PlainText
          color: root.dim
          wrapMode: Text.WordWrap
          maximumLineCount: 4
          elide: Text.ElideRight
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
        }

        Text {
          visible: root.editorError !== "" && (root.page === "hosts" || root.page === "actions")
          width: parent.width
          text: root.editorError
          textFormat: Text.PlainText
          color: Commons.Color.urgent
          wrapMode: Text.WordWrap
          maximumLineCount: 6
          elide: Text.ElideRight
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
        }

        Text {
          visible: root.deletePending
          width: parent.width
          text: strings.t("editor.working", "Working…")
          textFormat: Text.PlainText
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
        }

        Text {
          visible: root.tunnelStatus !== "" && (root.page === "hosts" || root.page === "actions")
          width: parent.width
          text: root.tunnelStatus
          textFormat: Text.PlainText
          color: root.tunnelBusyAction !== "" ? root.dim : Commons.Color.urgent
          wrapMode: Text.WordWrap
          maximumLineCount: 6
          elide: Text.ElideRight
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
        }

        Text {
          visible: root.page === "edit" || root.page === "setup" || root.hosts.length > 0
          width: parent.width
          text: root.page === "edit" ? strings.t("editor.keys", "Tab next · Shift+Tab back · ↵ save · Esc cancel")
            : root.page === "setup" ? strings.t("setup.keys", "↵ add the line · Esc back")
            : root.page === "actions" ? root.actionHint()
            : root.hostHint()
          textFormat: Text.PlainText
          color: root.dim
          wrapMode: Text.WordWrap
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
        }
      }

      ConfirmDialog {
        id: deleteConfirm
        anchors.fill: parent
        z: 10
        opened: root.deleteConfirmOpen
        message: (root.deleteTunnel
          ? strings.t("delete.confirmTunnel", "Delete %1 from omassh.config? Its running tunnel will be stopped.")
          : strings.t("delete.confirm", "Delete %1 from omassh.config?")).arg(root.deleteAlias)
        confirmText: Commons.I18n.t("common.delete")
        fontFamily: root.fontFamily
        onCanceled: root.cancelDelete()
        onConfirmed: root.confirmDelete()
      }

      Item {
        id: confirmKeys
        Keys.onPressed: function(event) {
          deleteConfirm.handleKey(event)
          event.accepted = true
        }
      }
    }
  }

  component HostRow: CursorSurface {
    id: row

    property var host: ({})
    property int rowIndex: 0
    readonly property string reachState: root.reach[root.aliasKey(host.alias)] || "unknown"
    readonly property bool tunnelUp: root.tunnelMap[root.aliasKey(host.alias)] === true
    readonly property bool tunnelBusy: root.tunnelBusyAction !== "" && root.tunnelBusyAlias === host.alias

    hasCursor: root.cursor === rowIndex
    foreground: root.fg
    implicitHeight: Math.max(rowText.implicitHeight, sftpButton.implicitHeight) + Style.spacing.rowPaddingX

    MouseArea {
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onContainsMouseChanged: if (containsMouse) root.cursor = row.rowIndex
      onClicked: root.connect(row.host, [])
    }

    RowLayout {
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(10)
      anchors.rightMargin: Style.space(6)
      spacing: Style.space(8)

      Rectangle {
        Layout.alignment: Qt.AlignVCenter
        width: Style.space(8)
        height: Style.space(8)
        radius: width / 2
        color: row.reachState === "up" ? Commons.Color.accent
             : row.reachState === "down" ? Commons.Color.urgent
             : Commons.Color.muted
        opacity: root.probed ? 1 : 0.5

        MouseArea {
          id: dotHover
          anchors.fill: parent
          anchors.margins: -Style.space(6)
          hoverEnabled: true
          acceptedButtons: Qt.NoButton
        }

        PanelToolTip {
          visible: dotHover.containsMouse
          fontFamily: root.fontFamily
          text: row.reachState === "up" ? strings.t("state.up", "reachable")
              : row.reachState === "down" ? strings.t("state.down", "not reachable")
              : strings.t("state.unknown", "not checked")
        }
      }

      ColumnLayout {
        id: rowText
        Layout.fillWidth: true
        spacing: Style.space(1)

        Text {
          Layout.fillWidth: true
          text: row.host.alias
          textFormat: Text.PlainText
          color: root.fg
          elide: Text.ElideRight
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
          font.bold: true
        }

        Text {
          Layout.fillWidth: true
          visible: text !== ""
          text: root.detailFor(row.host)
          textFormat: Text.PlainText
          color: root.dim
          elide: Text.ElideRight
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
        }
      }

      Text {
        visible: root.editorOn && row.host.origin !== "config"
        Layout.alignment: Qt.AlignVCenter
        text: "󰈔"
        textFormat: Text.PlainText
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.icon

        MouseArea {
          id: managedHover
          anchors.fill: parent
          anchors.margins: -Style.space(4)
          hoverEnabled: true
          acceptedButtons: Qt.NoButton
        }

        PanelToolTip {
          visible: managedHover.containsMouse
          fontFamily: root.fontFamily
          text: strings.t("row.managed", "Stored in omassh.config")
        }
      }

      Text {
        visible: row.tunnelUp || row.tunnelBusy
        Layout.alignment: Qt.AlignVCenter
        text: "󰌘"
        textFormat: Text.PlainText
        color: Commons.Color.accent
        opacity: row.tunnelBusy ? 0.5 : 1
        font.family: root.fontFamily
        font.pixelSize: Style.font.icon

        MouseArea {
          id: tunnelHover
          anchors.fill: parent
          anchors.margins: -Style.space(4)
          hoverEnabled: true
          acceptedButtons: Qt.NoButton
        }

        PanelToolTip {
          visible: tunnelHover.containsMouse
          fontFamily: root.fontFamily
          text: strings.t("row.tunnel", "Tunnel up")
        }
      }

      PanelActionButton {
        id: sftpButton
        iconText: "󰉋"
        tooltipText: strings.t("row.sftp", "Open SFTP")
        foreground: root.fg
        fontFamily: root.fontFamily
        Layout.alignment: Qt.AlignVCenter
        onClicked: root.connect(row.host, ["--sftp"])
      }

      PanelActionButton {
        iconText: row.host.pinned ? "󰐃" : "󰤱"
        tooltipText: row.host.pinned ? strings.t("row.unpin", "Unpin") : strings.t("row.pin", "Pin to top")
        foreground: root.fg
        fontFamily: root.fontFamily
        Layout.alignment: Qt.AlignVCenter
        onClicked: root.togglePin(row.host)
      }

      PanelActionButton {
        iconText: "󰅂"
        tooltipText: strings.t("row.more", "More actions")
        foreground: root.fg
        fontFamily: root.fontFamily
        Layout.alignment: Qt.AlignVCenter
        onClicked: root.openActions(row.host)
      }
    }
  }

  component ActionRow: CursorSurface {
    id: line

    property var entry: ({})
    property int rowIndex: 0

    hasCursor: root.actionCursor === rowIndex
    foreground: root.fg
    implicitHeight: lineText.implicitHeight + Style.spacing.rowPaddingX

    MouseArea {
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onContainsMouseChanged: if (containsMouse) root.actionCursor = line.rowIndex
      onClicked: root.runAction(root.actionHost, line.entry)
    }

    RowLayout {
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(10)
      anchors.rightMargin: Style.space(10)
      spacing: Style.space(8)

      Text {
        Layout.alignment: Qt.AlignVCenter
        Layout.preferredWidth: Style.space(20)
        horizontalAlignment: Text.AlignHCenter
        text: line.entry.glyph
        textFormat: Text.PlainText
        color: root.fg
        font.family: root.fontFamily
        font.pixelSize: Style.font.icon
      }

      ColumnLayout {
        id: lineText
        Layout.fillWidth: true
        spacing: Style.space(1)

        Text {
          Layout.fillWidth: true
          text: line.entry.label
          textFormat: Text.PlainText
          color: root.fg
          elide: Text.ElideRight
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
        }

        Text {
          Layout.fillWidth: true
          visible: text !== ""
          text: line.entry.detail
          textFormat: Text.PlainText
          color: root.dim
          elide: Text.ElideRight
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
        }
      }

      Text {
        Layout.alignment: Qt.AlignVCenter
        visible: text !== ""
        text: line.entry.key !== "" ? line.entry.key : (line.entry.id === "ssh" ? "↵" : "")
        textFormat: Text.PlainText
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
      }
    }
  }
}
