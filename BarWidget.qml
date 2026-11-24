import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Commons as Commons
import qs.Ui

BarWidget {
  id: root
  moduleName: "paulorivera27.omassh"

  readonly property bool opened: panelLoader.item ? panelLoader.item.opened === true : false
  readonly property int tunnelCount: panelLoader.item ? Math.max(0, Math.floor(Number(panelLoader.item.activeTunnels) || 0)) : 0

  /** Opens the panel. */
  function open() { if (panelLoader.item) panelLoader.item.open() }
  /** Closes the panel. */
  function close() { if (panelLoader.item) panelLoader.item.close() }
  /** Toggles the panel. */
  function togglePanel() { if (panelLoader.item) panelLoader.item.toggle() }
  /** Reloads the running tunnels shown by the badge. */
  function refreshTunnels() { if (panelLoader.item) panelLoader.item.loadTunnels() }

  readonly property Item openPanelIndicatorItem: letters
  readonly property bool popoutSwitchClosing: panelLoader.item ? panelLoader.item.popoutSwitchClosing === true : false

  /** Closes the panel because another popout is taking over. */
  function closeForPopoutSwitch() {
    if (panelLoader.item) panelLoader.item.closeForPopoutSwitch()
  }

  /** Hands the bar, the settings and this widget to the panel. */
  function injectPanel() {
    var target = panelLoader.item
    if (!target) return
    if ("bar" in target) target.bar = root.bar
    if ("settings" in target) target.settings = root.settings
    if ("anchorItem" in target) target.anchorItem = button
    if ("hostWidget" in target) target.hostWidget = root
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onBarChanged: injectPanel()
  onSettingsChanged: injectPanel()

  Loader {
    id: panelLoader
    active: true
    source: Qt.resolvedUrl("Panel.qml")
    visible: false
    onLoaded: {
      root.injectPanel()
      Qt.callLater(root.injectPanel)
    }
  }

  IpcHandler {
    target: "paulorivera27.omassh"

    /** Opens the panel. */
    function open(): void { root.open() }
    /** Closes the panel. */
    function close(): void { root.close() }
    /** Opens the panel. */
    function show(): void { root.open() }
    /** Closes the panel. */
    function hide(): void { root.close() }
    /** Toggles the panel. */
    function toggle(): void { root.togglePanel() }
  }

  Commons.Translations { id: strings; directory: Qt.resolvedUrl("i18n") }

  WidgetButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    labelVisible: false
    hasVisualContent: true
    tooltipText: root.tunnelCount > 0
      ? strings.tn("bar.tooltipTunnels", root.tunnelCount, "SSH hosts · %1 tunnels up").arg(Commons.I18n.formatNumber(root.tunnelCount))
      : strings.t("bar.tooltip", "SSH hosts")
    fixedWidth: root.vertical ? -1 : icon.width + Style.space(12)
    fixedHeight: root.vertical ? icon.height + Style.space(12) : -1

    onPressed: function(b) { root.togglePanel() }

    Item {
      id: letters
      x: icon.x
      y: icon.y
      width: 11 * icon.px
      height: icon.height
    }

    Canvas {
      id: icon

      readonly property var grid: [
        "###.###.#.#.oo",
        "#...#...#.#.oo",
        "###.###.###...",
        "..#...#.#.#...",
        "###.###.#.#..."
      ]
      readonly property int columns: 14
      readonly property int px: root.vertical
        ? Math.max(1, Math.min(Math.floor(Style.bar.iconSize / 5), Math.floor((root.barSize - Style.space(6)) / columns)))
        : Math.max(1, Math.floor(Style.bar.iconSize / 5))
      readonly property color ink: button.foreground
      readonly property color badge: Commons.Color.accent
      readonly property bool tunnelUp: root.tunnelCount > 0

      x: Math.round((button.width - width) / 2)
      y: Math.round((button.height - height) / 2)
      width: columns * px
      height: grid.length * px
      renderTarget: Canvas.Image
      antialiasing: false

      onPxChanged: requestPaint()
      onInkChanged: requestPaint()
      onBadgeChanged: requestPaint()
      onTunnelUpChanged: requestPaint()
      Component.onCompleted: requestPaint()

      onPaint: {
        var ctx = getContext("2d")
        ctx.clearRect(0, 0, width, height)
        for (let y = 0; y < grid.length; y++) {
          const row = grid[y]
          for (let x = 0; x < columns; x++) {
            const c = row.charAt(x)
            if (c === "#") ctx.fillStyle = Qt.rgba(ink.r, ink.g, ink.b, 1)
            else if (c === "o" && tunnelUp) ctx.fillStyle = Qt.rgba(badge.r, badge.g, badge.b, 1)
            else continue
            ctx.fillRect(x * px, y * px, px, px)
          }
        }
      }
    }
  }
}
