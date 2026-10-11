// SPDX-License-Identifier: Apache-2.0
// HyprNova :: status indicator
//
// A dot with an optional halo and an optional pulse. This is the single most
// repeated visual element in the console, and the halo is what carries meaning:
// `pulse: true` is reserved for states an operator must act on, so after a week of
// use the peripheral-vision response to a pulsing dot is trained rather than read.
//
// The glow is a second, larger, low-alpha circle rather than a blur effect.
// ShaderEffectSource/layer.effect costs an offscreen FBO per instance, and there
// are hundreds of these on the Threats page.

import QtQuick
import "../theme"

Item {
    id: root

    /// Base colour of the dot.
    property color color: Theme.textFaint
    /// Diameter of the solid core.
    property real size: 10
    /// Draw the halo ring. Implied by `pulse`.
    property bool glow: false
    /// Breathe the halo. Reserved for Critical/High and "waiting on you" states.
    property bool pulse: false
    /// Hollow instead of filled: used for "known but not currently active".
    property bool hollow: false

    implicitWidth: size
    implicitHeight: size

    // Halo. Two concentric rings read as a glow on both IPS and TN panels; a
    // single ring reads as an outline.
    Rectangle {
        id: haloOuter
        anchors.centerIn: parent
        width: root.size * 2.6
        height: width
        radius: width / 2
        color: "transparent"
        border.width: 1
        border.color: Theme.withAlpha(root.color, 0.10)
        visible: root.glow || root.pulse
        opacity: root.pulse ? 0.5 : 1.0
    }

    Rectangle {
        id: haloInner
        anchors.centerIn: parent
        width: root.size * 1.8
        height: width
        radius: width / 2
        color: Theme.withAlpha(root.color, root.hollow ? 0.06 : 0.16)
        border.width: root.hollow ? 1 : 0
        border.color: Theme.withAlpha(root.color, 0.45)
        visible: root.glow || root.pulse
        opacity: root.pulse ? 0.7 : 1.0
    }

    // Core.
    Rectangle {
        id: core
        anchors.centerIn: parent
        width: root.size
        height: root.size
        radius: width / 2
        color: root.hollow ? "transparent" : root.color
        border.width: root.hollow ? 2 : 0
        border.color: root.color
    }

    // Specular highlight: a small offset light spot sells "sphere" rather than
    // "circle" at 10 px, which is the whole reason the dashboard reads as
    // hardware rather than as a spreadsheet.
    Rectangle {
        anchors.centerIn: parent
        anchors.verticalCenterOffset: -root.size * 0.16
        width: root.size * 0.34
        height: width
        radius: width / 2
        color: Qt.rgba(1, 1, 1, 0.35)
        visible: !root.hollow && root.size >= 8
    }

    SequentialAnimation on opacity {
        running: root.pulse && root.visible
        loops: Animation.Infinite
        // Ease rather than linear: a linear pulse reads as a blinking error light,
        // an eased one reads as breathing, which is far less fatiguing on a
        // dashboard that stays up for days.
        NumberAnimation { from: 1.0; to: 0.35; duration: Theme.pulseMs; easing.type: Easing.InOutSine }
        NumberAnimation { from: 0.35; to: 1.0; duration: Theme.pulseMs; easing.type: Easing.InOutSine }
    }

    // Cancel the animation when the row scrolls out of view; a ListView with 2000
    // events otherwise keeps 2000 timers alive.
    onVisibleChanged: if (!visible) opacity = 1.0
}
