// SPDX-License-Identifier: Apache-2.0
// HyprNova :: risk bar
//
// Risk is 0..1000 internally, but a bar showing "743" is not comparable at a
// glance across rows. The bar carries the magnitude, the number carries the
// precision, and the colour carries the band — three redundant encodings, because
// the operator may be colour-blind, may be reading a greyscale screenshot in a
// report, or may be looking at it from across a room.

import QtQuick
import QtQuick.Controls
import "../theme"

Item {
    id: root

    /// 0..1000.
    property real risk: 0
    /// Show the numeric value beside the bar.
    property bool showValue: true
    property bool compact: false

    readonly property real norm: Math.max(0, Math.min(1000, Number(root.risk) || 0)) / 1000.0
    readonly property color bandColor: Theme.riskColor(root.risk)

    implicitHeight: root.compact ? 6 : 18
    implicitWidth: root.compact ? 56 : 132

    Row {
        anchors.fill: parent
        spacing: Theme.space2

        Item {
            width: root.showValue && !root.compact ? parent.width - 40 - Theme.space2 : parent.width
            height: parent.height

            // Track.
            Rectangle {
                id: track
                anchors { left: parent.left; right: parent.right; verticalCenter: parent.verticalCenter }
                height: root.compact ? 4 : 6
                radius: height / 2
                color: Theme.surfaceAlt
                border.width: 1
                border.color: Theme.borderSoft

                // Fill.
                Rectangle {
                    width: track.width * root.norm
                    height: track.height
                    radius: track.radius
                    color: root.bandColor
                    // Animate the width, not the value: risk accumulates smoothly
                    // in the engine (exponential decay per second), so a stepped
                    // bar would misrepresent it.
                    Behavior on width { NumberAnimation { duration: Theme.animSlow; easing.type: Easing.OutCubic } }
                }

                // Threshold ticks at the alert / critical / auto-respond points, so
                // the operator can see how close an actor is to the line the agent
                // will act on without reading the config.
                Repeater {
                    model: root.thresholds
                    Rectangle {
                        required property real position
                        required property color color
                        x: track.width * position
                        width: 1
                        height: track.height + 6
                        y: -3
                        color: Theme.withAlpha(parent.bandColor, 0.55)
                        visible: !root.compact
                    }
                }
            }

            // Head glow: only above the alert threshold, i.e. only when it matters.
            Rectangle {
                anchors { verticalCenter: track.verticalCenter }
                x: track.width * root.norm - 3
                width: 6
                height: 6
                radius: 3
                color: root.bandColor
                visible: root.norm > root.glowFrom
                opacity: 0.9

                SequentialAnimation on opacity {
                    running: root.norm > root.glowFrom && root.visible
                    loops: Animation.Infinite
                    NumberAnimation { to: 0.35; duration: Theme.pulseMs / 2; easing.type: Easing.InOutSine }
                    NumberAnimation { to: 0.95; duration: Theme.pulseMs / 2; easing.type: Easing.InOutSine }
                }
            }
        }

        Label {
            visible: root.showValue && !root.compact
            text: Math.round(root.risk)
            color: root.bandColor
            width: 40
            horizontalAlignment: Text.AlignRight
            verticalAlignment: Text.AlignVCenter
            height: parent.height
            font {
                pixelSize: Theme.fontSizeSmall
                family: Theme.monoFamily
                weight: Theme.weightBold
            }
        }
    }

    /// 0..1 fractions at which to draw threshold ticks. Set by the page from the
    /// agent's configured thresholds.
    property var thresholds: []
    /// Fraction above which the head glows.
    property real glowFrom: 0.55
}
