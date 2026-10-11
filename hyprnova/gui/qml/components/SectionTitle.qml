// SPDX-License-Identifier: Apache-2.0
// HyprNova :: section title with an integral rule
//
// The rule runs to the right edge of the available width, which is what makes a
// stack of sections read as one document rather than as floating labels.

import QtQuick
import QtQuick.Controls
import "../theme"

Row {
    id: root

    property string text: ""
    property string detail: ""
    property color color: Theme.textDim
    /// Right-aligned slot: a count, a filter, a refresh button.
    default property alias trailing: trailing.data

    spacing: Theme.space3
    width: parent ? parent.width : implicitWidth
    height: label.height

    Label {
        id: label
        text: root.text.toUpperCase()
        color: root.color
        font {
            pixelSize: Theme.fontSizeSmall
            family: Theme.fontFamily
            weight: Theme.weightBold
            letterSpacing: 1.4
        }
        anchors.verticalCenter: parent.verticalCenter
    }

    Label {
        text: root.detail
        visible: root.detail.length > 0
        color: Theme.textFaint
        font.pixelSize: Theme.fontSizeSmall
        font.family: Theme.monoFamily
        anchors.verticalCenter: parent.verticalCenter
    }

    Rectangle {
        // Fills the remaining width; height 1 with a border tone rather than a
        // gradient so it stays crisp at any DPI scale factor.
        width: Math.max(0, root.width - label.width - trailing.width
                        - (root.detail.length > 0 ? root.detail.length * 7 + Theme.space3 * 2 : Theme.space3))
        height: 1
        anchors.verticalCenter: parent.verticalCenter
        color: Theme.border
    }

    Row {
        id: trailing
        spacing: Theme.space2
        anchors.verticalCenter: parent.verticalCenter
    }
}
