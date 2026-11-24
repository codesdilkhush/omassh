import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import qs.Commons
import qs.Commons as Commons
import qs.Ui

FocusScope {
  id: form

  required property var strings
  property color fg: Commons.Color.foreground
  property color dim: Qt.darker(fg, 1.5)
  property string fontFamily: Style.font.family
  property var errors: []
  property bool busy: false
  property int maxHeight: Style.space(380)
  property var forwardRows: []
  property int pendingRow: -1
  readonly property int forwardLimit: 16

  signal saveRequested()
  signal cancelRequested()
  signal rowRemoved(int row)

  implicitHeight: layout.implicitHeight
  Keys.onPressed: function(event) { form.handleKey(event, form) }

  /** Returns the error code of a field without a row, or an empty string. */
  function fieldError(name) {
    for (var i = 0; i < form.errors.length; i++)
      if (form.errors[i].field === name && form.errors[i].index < 0) return form.errors[i].code
    return ""
  }

  /** Returns the error code of one forward row, or an empty string. */
  function rowError(row) {
    for (var i = 0; i < form.errors.length; i++)
      if (form.errors[i].field === "forwards" && form.errors[i].index === row) return form.errors[i].code
    return ""
  }

  /** Returns the translated message of an error code of a field. */
  function errorText(field, code) {
    if (code === "") return ""
    if (code === "required") return form.strings.t("error.required", "This field is required.")
    if (code === "too-long") return form.strings.t("error.tooLong", "This value is too long.")
    if (code === "port") return form.strings.t("error.port", "Use a port from 1 to 65535.")
    if (code === "too-many") return form.strings.t("error.tooMany", "Too many forwards.")
    if (code === "duplicate") return form.strings.t("error.duplicate", "This forward is listed twice.")
    if (code === "taken") return form.strings.t("error.taken", "This name is already used in your SSH config.")
    if (code === "not-found") return form.strings.t("error.notFound", "No such file.")
    if (code === "self") return form.strings.t("error.self", "A host cannot jump through itself.")
    if (code === "forward") return form.strings.t("error.forward", "Use L 8080 localhost:80, R 9000 localhost:22 or D 1080.")
    if (code === "hop") return form.strings.t("error.hop", "Use [user@]host[:port], separated by commas (at most 8).")
    if (code === "cycle") return form.strings.t("error.cycle", "These jump hosts lead back to this host.")
    if (field === "alias") return form.strings.t("error.invalidAlias", "Start with a letter or digit, then use letters, digits, . _ or -.")
    if (field === "hostname") return form.strings.t("error.invalidHostname", "Use a host name or an IP address, without brackets.")
    if (field === "user") return form.strings.t("error.invalidUser", "Use letters, digits, . _ or -, and do not start with -.")
    if (field === "identityFile") return form.strings.t("error.invalidIdentityFile", "Use an absolute path or one starting with ~/, without spaces.")
    if (field === "port") return form.strings.t("error.port", "Use a port from 1 to 65535.")
    if (field === "proxyJump") return form.strings.t("error.hop", "Use [user@]host[:port], separated by commas (at most 8).")
    if (field === "forwards") return form.strings.t("error.forward", "Use L 8080 localhost:80, R 9000 localhost:22 or D 1080.")
    return form.strings.t("error.invalid", "This value is not valid.")
  }

  /** Returns the current text of every forward row. */
  function forwardTexts() {
    var out = []
    for (var i = 0; i < form.forwardRows.length; i++) {
      var item = forwardRepeater.itemAt(i)
      out.push(item ? item.input.text : "")
    }
    return out
  }

  /** Returns the field inputs in the order Tab visits them. */
  function focusables() {
    var out = [aliasField.input, hostnameField.input, userField.input, portField.input, proxyField.input, identityField.input]
    for (var i = 0; i < form.forwardRows.length; i++) {
      var item = forwardRepeater.itemAt(i)
      if (item) out.push(item.input)
    }
    if (addForward.enabled) out.push(addForward)
    return out
  }

  /** Fills the form from a host of the plugin file, or empties it for a new host. */
  function load(host) {
    var values = host || ({})
    aliasField.text = typeof values.alias === "string" ? values.alias : ""
    hostnameField.text = typeof values.hostname === "string" ? values.hostname : ""
    userField.text = typeof values.user === "string" ? values.user : ""
    portField.text = typeof values.port === "string" ? values.port : ""
    proxyField.text = typeof values.proxyJump === "string" ? values.proxyJump : ""
    identityField.text = typeof values.identityFile === "string" ? values.identityFile : ""
    form.forwardRows = Array.isArray(values.forwards) ? values.forwards.slice(0, form.forwardLimit) : []
    flick.contentY = 0
  }

  /** Returns what was typed, every value as a string. */
  function values() {
    return {
      alias: aliasField.text,
      hostname: hostnameField.text,
      user: userField.text,
      port: portField.text,
      proxyJump: proxyField.text,
      identityFile: identityField.text,
      forwards: form.forwardTexts()
    }
  }

  /** Gives focus to the field at position index, counting from the end when negative. */
  function focusField(index) {
    var list = form.focusables()
    list[index < 0 ? list.length + index : Math.min(index, list.length - 1)].forceActiveFocus()
  }

  /** Moves focus one field forward or back, wrapping around. */
  function step(item, direction) {
    var list = form.focusables()
    list[(list.indexOf(item) + direction + list.length) % list.length].forceActiveFocus()
  }

  /** Gives focus to the first field that has an error. */
  function focusFirstError() {
    var first = [["alias", aliasField], ["hostname", hostnameField], ["user", userField], ["port", portField], ["proxyJump", proxyField], ["identityFile", identityField]]
    for (var i = 0; i < first.length; i++)
      if (form.fieldError(first[i][0]) !== "") { first[i][1].input.forceActiveFocus(); form.reveal(first[i][1]); return }
    for (var j = 0; j < form.errors.length; j++) {
      var item = form.errors[j].field === "forwards" ? forwardRepeater.itemAt(form.errors[j].index) : null
      if (item) { item.input.forceActiveFocus(); form.reveal(item); return }
    }
    if (form.fieldError("forwards") !== "") form.focusField(-1)
  }

  /** Adds an empty forward row and focuses it. */
  function addRow() {
    if (form.forwardRows.length >= form.forwardLimit) return
    var texts = form.forwardTexts()
    form.pendingRow = texts.length
    form.forwardRows = texts.concat([""])
  }

  /** Removes one forward row and keeps the text of the others. */
  function removeRow(row) {
    var texts = form.forwardTexts()
    texts.splice(row, 1)
    form.forwardRows = texts
    form.rowRemoved(row)
    form.focusField(6 + Math.min(row, texts.length))
    form.reveal(form.focusables()[6 + Math.min(row, texts.length)])
  }

  /** Scrolls the form so that item is in view once the layout has settled. */
  function reveal(item) {
    Qt.callLater(form.place, item)
  }

  /** Moves the scroll position so that item is fully visible. */
  function place(item) {
    content.forceLayout()
    var top = item.mapToItem(content, 0, 0).y - Style.space(18)
    var bottom = item.mapToItem(content, 0, item.height).y + Style.space(4)
    if (top < flick.contentY) flick.contentY = Math.max(0, top)
    else if (bottom > flick.contentY + flick.height) flick.contentY = Math.min(bottom - flick.height, Math.max(0, flick.contentHeight - flick.height))
  }

  /** Handles Tab, Shift+Tab, Enter and Escape for the field item. */
  function handleKey(event, item) {
    var back = event.key === Qt.Key_Backtab || (event.key === Qt.Key_Tab && (event.modifiers & Qt.ShiftModifier))
    if (event.key === Qt.Key_Escape) {
      form.cancelRequested()
      event.accepted = true
    } else if (back || event.key === Qt.Key_Tab) {
      form.step(item, back ? -1 : 1)
      event.accepted = true
    } else if (item !== addForward && (event.key === Qt.Key_Return || event.key === Qt.Key_Enter)) {
      form.saveRequested()
      event.accepted = true
    }
  }

  component Input: TextField {
    id: input

    readOnly: form.busy
    selectByMouse: true
    inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
    foreground: form.fg
    Keys.priority: Keys.BeforeItem
    Keys.onPressed: function(event) { form.handleKey(event, input) }
    onActiveFocusChanged: if (activeFocus) form.reveal(input)
  }

  component FieldBlock: Column {
    id: block

    property string name: ""
    property string label: ""
    property string placeholder: ""
    property int maximumLength: 0
    property alias text: field.text
    property alias input: field

    width: parent.width
    spacing: Style.space(3)

    Text {
      width: parent.width
      text: block.label
      textFormat: Text.PlainText
      color: form.dim
      elide: Text.ElideRight
      font.family: form.fontFamily
      font.pixelSize: Style.font.caption
    }

    Input {
      id: field
      width: parent.width
      placeholderText: block.placeholder
      maximumLength: block.maximumLength
    }

    Text {
      visible: text !== ""
      width: parent.width
      text: form.errorText(block.name, form.fieldError(block.name))
      textFormat: Text.PlainText
      color: Commons.Color.urgent
      wrapMode: Text.WordWrap
      font.family: form.fontFamily
      font.pixelSize: Style.font.caption
    }
  }

  Column {
    id: layout
    width: parent.width
    spacing: Style.space(8)

    Flickable {
      id: flick
      width: parent.width
      height: Math.min(content.implicitHeight, form.maxHeight)
      contentWidth: width
      contentHeight: content.implicitHeight
      clip: true
      boundsBehavior: Flickable.StopAtBounds
      interactive: contentHeight > height
      ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

      Column {
        id: content
        width: flick.width - (flick.interactive ? Style.space(10) : 0)
        spacing: Style.space(8)

        FieldBlock {
          id: aliasField
          name: "alias"
          label: form.strings.t("field.alias", "Name (Host)")
          placeholder: "web"
          maximumLength: 128
        }

        FieldBlock {
          id: hostnameField
          name: "hostname"
          label: form.strings.t("field.hostname", "Address (HostName)")
          placeholder: "web.example.com"
          maximumLength: 253
        }

        FieldBlock {
          id: userField
          name: "user"
          label: form.strings.t("field.user", "User")
          placeholder: "admin"
          maximumLength: 64
        }

        FieldBlock {
          id: portField
          name: "port"
          label: form.strings.t("field.port", "Port")
          placeholder: "22"
          maximumLength: 5
        }

        FieldBlock {
          id: proxyField
          name: "proxyJump"
          label: form.strings.t("field.proxyJump", "Jump hosts (ProxyJump)")
          placeholder: "bastion.example.com"
          maximumLength: 1024
        }

        FieldBlock {
          id: identityField
          name: "identityFile"
          label: form.strings.t("field.identityFile", "Key file (IdentityFile)")
          placeholder: "~/.ssh/id_ed25519"
          maximumLength: 1024
        }

        Column {
          width: parent.width
          spacing: Style.space(3)

          Text {
            width: parent.width
            text: form.strings.t("actions.forwards", "Port forwards")
            textFormat: Text.PlainText
            color: form.dim
            elide: Text.ElideRight
            font.family: form.fontFamily
            font.pixelSize: Style.font.caption
          }

          Text {
            width: parent.width
            text: form.strings.t("field.forwardsHelp", "L local · R remote · D dynamic (SOCKS)")
            textFormat: Text.PlainText
            color: form.dim
            elide: Text.ElideRight
            font.family: form.fontFamily
            font.pixelSize: Style.font.caption
          }

          Text {
            visible: text !== ""
            width: parent.width
            text: form.errorText("forwards", form.fieldError("forwards"))
            textFormat: Text.PlainText
            color: Commons.Color.urgent
            wrapMode: Text.WordWrap
            font.family: form.fontFamily
            font.pixelSize: Style.font.caption
          }
        }

        Repeater {
          id: forwardRepeater
          model: form.forwardRows
          onItemAdded: function(index, item) {
            if (index !== form.pendingRow) return
            form.pendingRow = -1
            item.input.forceActiveFocus()
            form.reveal(item.input)
          }

          delegate: Column {
            id: forwardItem

            required property string modelData
            required property int index
            property alias input: forwardInput

            width: content.width
            spacing: Style.space(3)

            RowLayout {
              width: parent.width
              spacing: Style.space(6)

              Input {
                id: forwardInput
                Layout.fillWidth: true
                text: forwardItem.modelData
                placeholderText: "L 8080 localhost:80"
                maximumLength: 300
              }

              PanelActionButton {
                Layout.alignment: Qt.AlignVCenter
                iconText: "󰅖"
                tooltipText: form.strings.t("field.removeForward", "Remove forward")
                foreground: form.fg
                fontFamily: form.fontFamily
                enabled: !form.busy
                onClicked: form.removeRow(forwardItem.index)
              }
            }

            Text {
              visible: text !== ""
              width: parent.width
              text: form.errorText("forwards", form.rowError(forwardItem.index))
              textFormat: Text.PlainText
              color: Commons.Color.urgent
              wrapMode: Text.WordWrap
              font.family: form.fontFamily
              font.pixelSize: Style.font.caption
            }
          }
        }

        Button {
          id: addForward
          focusable: true
          iconText: "󰐕"
          text: form.strings.t("field.addForward", "Add forward")
          foreground: form.fg
          fontFamily: form.fontFamily
          fontSize: Style.font.bodySmall
          leftAlign: true
          enabled: !form.busy && form.forwardRows.length < form.forwardLimit
          Keys.priority: Keys.BeforeItem
          Keys.onPressed: function(event) { form.handleKey(event, addForward) }
          onActiveFocusChanged: if (activeFocus) form.reveal(addForward)
          onClicked: form.addRow()
        }
      }
    }

    Item {
      width: parent.width
      height: buttons.implicitHeight

      Text {
        visible: form.busy
        anchors.left: parent.left
        anchors.verticalCenter: parent.verticalCenter
        text: form.strings.t("editor.working", "Working…")
        textFormat: Text.PlainText
        color: form.dim
        font.family: form.fontFamily
        font.pixelSize: Style.font.caption
      }

      Row {
        id: buttons
        anchors.right: parent.right
        spacing: Style.space(8)

        Button {
          text: Commons.I18n.t("common.cancel")
          foreground: form.fg
          fontFamily: form.fontFamily
          fontSize: Style.font.bodySmall
          bordered: true
          onClicked: form.cancelRequested()
        }

        Button {
          text: form.strings.t("editor.save", "Save")
          foreground: form.fg
          fontFamily: form.fontFamily
          fontSize: Style.font.bodySmall
          bordered: true
          enabled: !form.busy
          onClicked: form.saveRequested()
        }
      }
    }
  }
}
