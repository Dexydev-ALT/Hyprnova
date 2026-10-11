// SPDX-License-Identifier: Apache-2.0
// HyprNova :: empty state
//
// An EDR console's empty states are semantically loaded and must never be
// generic. "No data" is a bug report; "No findings in the last hour — all
// sensors reporting" is an assurance. Every panel passes an explicit `message`,
// and this component's job is to make the quiet case look intentionally quiet
// rather than broken.

import QtQuick
import QtQuick.Controls
import "../theme"

Column {
    id: root

    property string message: ""
    property string hint: ""
    /// Green-and-calm for "nothing is wrong", neutral for "nothing loaded yet".
    property bool good: false
    default property alias action: actionSlot.data

    spacing: Theme.space2
    anchors.centerIn: parent
    width: parent ? parent.width : implicitWidth
    visible: message.length > 0

    GlowDot {
        anchors.horizontalCenter: parent.horizontalCenter
        size: 14
        color: root.good ? Theme.ok : Theme.textFaint
        glow: true
        pulse: false
    }

    Label {
        text: root.message
        anchors.horizontalCenter: parent.horizontalCenter
        horizontalAlignment: Text.AlignHCenter
        color: root.good ? Theme.textDim : Theme.textDim
        font {
            pixelSize: Theme.fontSizeBody
            family: Theme.fontFamily
            weight: Theme.weightMedium
        }
        wrapMode: Text.WordWrap
        width: Math.min(parent.width - Theme.space5, 420)
    }

    Label {
        text: root.hint
        visible: root.hint.length > 0
        anchors.horizontalCenter: parent.horizontalCenter
        horizontalAlignment: Text.AlignHCenter
        color: Theme.textFaint
        font.pixelSize: Theme.fontSizeSmall
        font.family: Theme.fontFamily
        wrapMode: Text.WordWrap
        width: Math.min(parent.width - Theme.space5, 420)
    }

    Row {
        id: actionSlot
        anchors.horizontalCenter: parent.horizontalCenter
        spacing: Theme.space2
    }
}
