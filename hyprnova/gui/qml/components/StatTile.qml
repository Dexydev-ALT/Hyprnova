// SPDX-License-Identifier: Apache-2.0
// HyprNova :: stat tile — one number, one label, optional trend
//
// The dashboard's top row is eight of these. They are deliberately identical in
// shape so the eye compares VALUES rather than layouts, and the number uses
// tabular figures so a change from 9 to 10 does not shift the column beside it.

import QtQuick
import QtQuick.Controls
import "../theme"

Panel {
    id: root

    property string label: ""
    property string value: "0"
    property string hint: ""
    /// Colour of the value. Defaults to plain text; set to a severity colour when
    /// the number itself is the alert (dropped events, pending decisions).
    property color valueColor: Theme.text
    property bool alarm: false
    /// Optional 0..1 progress underlay, for "learning" style tiles.
    property real progress: -1.0
    property color progressColor: Theme.accent
    /// Optional delta text, e.g. "+12 / min".
    property string delta: ""

    showAccent: false
    pad: Theme.space3
    title: ""
    implicitWidth: 168
    implicitHeight: 86

    // Alarm state: a tinted fill plus a glow border. Used sparingly — at most one
    // or two tiles on the dashboard should ever be in this state at once.
    color: root.alarm ? Theme.withAlpha(root.valueColor, 0.08) : Theme.surface
    border.color: root.alarm ? Theme.withAlpha(root.valueColor, 0.55) : Theme.border

    SequentialAnimation on border.color {
        running: root.alarm && root.visible
        loops: Animation.Infinite
        ColorAnimation { to: Theme.withAlpha(root.valueColor, 0.15); duration: Theme.pulseMs; easing.type: Easing.InOutSine }
        ColorAnimation { to: Theme.withAlpha(root.valueColor, 0.55); duration: Theme.pulseMs; easing.type: Easing.InOutSine }
    }

    Column {
        anchors { fill: parent; margins: Theme.space3 }
        spacing: 2

        Label {
            text: root.label.toUpperCase()
            color: Theme.textFaint
            font {
                pixelSize: Theme.fontSizeMicro
                family: Theme.fontFamily
                weight: Theme.weightMedium
                letterSpacing: 1.1   // tracked-out micro caps: reads as instrumentation
            }
            elide: Text.ElideRight
            width: parent.width
        }

        Row {
            width: parent.width
            spacing: Theme.space2
            layoutDirection: Qt.RightToLeft   // delta right-aligned, value left

            Label {
                text: root.delta
                visible: root.delta.length > 0
                color: Theme.textFaint
                font.pixelSize: Theme.fontSizeSmall
                font.family: Theme.monoFamily
                verticalAlignment: Text.AlignBottom
                anchors.verticalCenter: parent.verticalCenter
            }

            Label {
                text: root.value
                color: root.valueColor
                width: parent.width - (root.delta.length > 0 ? parent.children[0].width + Theme.space2 : 0)
                font {
                    pixelSize: Theme.fontSizeTitle
                    family: Theme.monoFamily
                    weight: Theme.weightBold
                }
                // Tabular figures stop the digits jittering as values change. This
                // is the difference between a readable live dashboard and one that
                // flickers.
                font.features: Font.TabularNumbers
                elide: Text.ElideRight
                verticalAlignment: Text.AlignVCenter
            }
        }

        Label {
            text: root.hint
            visible: root.hint.length > 0
            color: Theme.textDim
            font.pixelSize: Theme.fontSizeSmall
            font.family: Theme.fontFamily
            elide: Text.ElideRight
            width: parent.width
        }

        Item { width: parent.width; height: 4; visible: root.progress >= 0 }

        // Progress underlay.
        Rectangle {
            width: parent.width
            height: 3
            radius: 2
            visible: root.progress >= 0
            color: Theme.surfaceAlt

            Rectangle {
                width: parent.width * Math.max(0, Math.min(1, root.progress))
                height: parent.height
                radius: 2
                color: root.progressColor
                // Animate width so a learning bar advances smoothly rather than
                // stepping once per refresh tick.
                Behavior on width { NumberAnimation { duration: Theme.animSlow; easing.type: Easing.OutCubic } }
            }
        }
    }

    ToolTip.visible: root.hint.length > 0 && mouse.containsMouse
    ToolTip.text: root.hint
    ToolTip.delay: 400
    HoverHandler { id: mouse }
}
