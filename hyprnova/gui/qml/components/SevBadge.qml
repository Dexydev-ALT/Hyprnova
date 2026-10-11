// SPDX-License-Identifier: Apache-2.0
// HyprNova :: severity / state pill
//
// One component for every coloured label in the console, so "critical" looks
// identical in the feed, the risk table, the scan results and the action journal.
// Consistency here is a safety property: an operator who has learned the pill on
// one page recognises it on another in peripheral vision.

import QtQuick
import QtQuick.Controls
import "../theme"

Rectangle {
    id: root

    /// Text to show. Also drives the colour when `autoColor` is set.
    property string text: ""
    /// Force a colour instead of deriving one from the text.
    property color customColor: Theme.textFaint
    /// Derive the colour from `text` as a severity name.
    property bool autoColor: true
    /// Derive from `text` as a sensor state name instead.
    property bool stateStyle: false
    /// Derive from `text` as a scan verdict instead.
    property bool verdictStyle: false
    /// Solid fill rather than tinted-outline. Reserved for the top alert banner.
    property bool solid: false
    /// Blink. Only for an unanswered escalation prompt.
    property bool pulse: false

    readonly property color resolvedColor: {
        if (!root.autoColor) return root.customColor;
        if (root.stateStyle) return Theme.sensorStateColor(root.text);
        if (root.verdictStyle) return Theme.verdictColor(root.text);
        return Theme.severityColor(root.text);
    }

    implicitHeight: 20
    implicitWidth: label.implicitWidth + Theme.space3 * 2
    radius: Theme.radiusPill
    color: root.solid ? resolvedColor : Theme.withAlpha(resolvedColor, 0.13)
    border.width: root.solid ? 0 : 1
    border.color: Theme.withAlpha(resolvedColor, root.solid ? 0 : 0.55)

    Label {
        id: label
        anchors.centerIn: parent
        text: root.text.toUpperCase()
        color: root.solid ? Theme.textOnAccent : root.resolvedColor
        font {
            pixelSize: Theme.fontSizeMicro
            family: Theme.fontFamily
            weight: Theme.weightBold
            letterSpacing: 0.9
        }
    }

    SequentialAnimation on opacity {
        running: root.pulse && root.visible
        loops: Animation.Infinite
        NumberAnimation { to: 0.45; duration: Theme.pulseMs / 2; easing.type: Easing.InOutSine }
        NumberAnimation { to: 1.0;  duration: Theme.pulseMs / 2; easing.type: Easing.InOutSine }
    }
}
