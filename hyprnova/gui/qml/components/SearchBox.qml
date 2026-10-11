// SPDX-License-Identifier: Apache-2.0
// HyprNova :: SearchBox -- the top-bar search field.
//
// Enter (or the magnifier) raises `searchCommitted(text)`; the shell decides
// where that lands (Threats, pre-filtered). Esc clears and gives focus back to
// the page. Styled like the reference app: rounded track, magnifier on the
// left, placeholder "Search (Ctrl+F)".

import QtQuick
import QtQuick.Controls
import "../theme"
import "."

Rectangle {
    id: box

    signal searchCommitted(string text)

    property alias text: field.text
    readonly property bool active: field.activeFocus

    width: 340
    height: 34
    radius: height / 2
    color: Theme.searchBg
    border.width: active ? 1 : 0
    border.color: Theme.accentDim

    function focusField() { field.forceActiveFocus(); field.selectAll(); }

    Row {
        anchors { fill: parent; leftMargin: 12; rightMargin: 10 }
        spacing: 8

        NavIcon {
            name: "search"
            color: field.activeFocus ? Theme.text : Theme.textFaint
            anchors.verticalCenter: parent.verticalCenter
            width: 16; height: 16
        }

        TextInput {
            id: field
            anchors.verticalCenter: parent.verticalCenter
            width: parent.width - 16 - 8 - 14
            color: Theme.text
            font {
                pixelSize: Theme.fontSizeBody
                family: Theme.fontFamily
            }
            clip: true
            verticalAlignment: TextInput.AlignVCenter
            selectByMouse: true
            onAccepted: box.searchCommitted(text)
            Keys.onEscapePressed: { text = ""; box.focus = false; }

            Text {
                visible: field.text.length === 0 && !field.activeFocus
                text: qsTr("Search (Ctrl+F)")
                color: Theme.textFaint
                font: field.font
                anchors.verticalCenter: parent.verticalCenter
            }
        }
    }

    // clear ("x") affordance once there is something to clear
    AbstractButton {
        visible: field.text.length > 0
        width: 18; height: 18
        anchors { right: parent.right; rightMargin: 10; verticalCenter: parent.verticalCenter }
        contentItem: NavIcon {
            name: "close"
            color: parent.hovered ? Theme.text : Theme.textFaint
            width: 12; height: 12
            anchors.centerIn: parent
        }
        background: Item {}
        onClicked: { field.text = ""; field.forceActiveFocus(); }
    }
}
