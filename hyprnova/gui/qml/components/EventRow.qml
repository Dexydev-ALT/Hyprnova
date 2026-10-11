// SPDX-License-Identifier: Apache-2.0
// HyprNova :: event row
//
// One rendering of one telemetry event, shared by the Dashboard preview, the
// Threats feed and the Remediation page. An event's *shape* is what an operator
// learns: severity spine, clock, sensor, message, actor. If three pages render it
// three ways, nobody learns it.
//
// Two implementation notes that are load-bearing:
//
//   * Every field is optional-tolerant. The bus emits ~40 kinds of event and a new
//     sensor will not populate all of them; a row that blanks out or throws on a
//     missing `actor.exe` would take the whole feed with it.
//   * The columns are ANCHORED, not laid out in a Row with arithmetic widths. A Row
//     needs each child's width to be computable, which means the flexible message
//     column ends up as `parent.width - (sum of the others) - (spacing * n)`. That
//     expression silently goes negative when a column becomes visible, and negative
//     widths are how you get a feed that renders nothing with no error message.
//     Anchors make the message column "whatever is left between the fixed left
//     columns and the fixed right columns", which cannot go wrong.

import QtQuick
import QtQuick.Controls
import "../theme"

Rectangle {
    id: root

    /// The event map: {id, ts, sensor, kind, severity, severity_rank, message,
    /// risk, metric, count, escalated, triggers, actor{...}, target{...}}
    property var event: null
    /// Compact variant for the dashboard preview: no badge, no target, no pid.
    property bool compact: false
    /// Show the target/path column. Off where width is scarce.
    property bool showTarget: true

    signal clicked(var event)
    signal investigateRequested(int pid)

    readonly property string severity: (event && event.severity !== undefined) ? String(event.severity) : "info"
    readonly property color sevColor: Theme.severityColor(severity)
    readonly property int rank: event ? (event.severity_rank || 0) : 0
    readonly property bool escalated: event ? event.escalated === true : false
    readonly property int pid: (event && event.actor && event.actor.pid) ? event.actor.pid : 0

    implicitHeight: root.compact ? 26 : Theme.rowHeight
    radius: Theme.radiusSm
    color: rowHover.containsMouse ? Theme.surfaceAlt
         : root.escalated ? Theme.withAlpha(root.sevColor, 0.06)
         : "transparent"

    // Severity spine. Two pixels, full height, in the severity colour: it lets a
    // 2000-row feed be scanned by colour alone, which is the only way to find the
    // one critical in a wall of info.
    Rectangle {
        anchors { left: parent.left; top: parent.top; bottom: parent.bottom }
        width: 2
        radius: 1
        color: root.sevColor
        opacity: root.rank >= 4 ? 1.0 : 0.6
    }

    // Glow border for critical/high only. Restrictive on purpose: if every row
    // glows, the operator learns to ignore all of them.
    Rectangle {
        anchors.fill: parent
        radius: parent.radius
        color: "transparent"
        border.width: 1
        border.color: Theme.withAlpha(root.sevColor, 0.20)
        visible: Theme.shouldGlow(root.severity)
    }

    // ---- fixed left columns ----
    Label {
        id: clock
        anchors { left: parent.left; leftMargin: Theme.space3; verticalCenter: parent.verticalCenter }
        width: root.compact ? 58 : 66
        text: Theme.formatClock(root.event ? root.event.ts : 0)
        color: Theme.textFaint
        font {
            pixelSize: Theme.fontSizeSmall
            family: Theme.monoFamily
        }
    }

    SevBadge {
        id: badge
        anchors { left: clock.right; leftMargin: Theme.space2; verticalCenter: parent.verticalCenter }
        visible: !root.compact
        text: root.severity
    }

    Label {
        id: sensor
        // Knowing WHICH sensor fired is what lets an analyst judge whether to
        // believe the finding, so it is a column, not a tooltip.
        anchors { left: root.compact ? clock.right : badge.right
                  leftMargin: Theme.space2; verticalCenter: parent.verticalCenter }
        width: root.compact ? 74 : 92
        text: root.event ? String(root.event.sensor || "") : ""
        color: Theme.textDim
        elide: Text.ElideRight
        font { pixelSize: Theme.fontSizeSmall; family: Theme.monoFamily }
    }

    GlowDot {
        id: escDot
        // Escalation marker: this event already made the agent freeze and inspect
        // something. It is the transition from "observed" to "acted on".
        anchors { left: sensor.right; leftMargin: Theme.space2; verticalCenter: parent.verticalCenter }
        visible: root.escalated
        size: 7
        color: Theme.critical
        glow: true
        pulse: true
        ToolTip.visible: escHover.containsMouse
        ToolTip.text: qsTr("Escalated: the agent froze this process and inspected it")
        ToolTip.delay: 250
        HoverHandler { id: escHover }
    }

    // ---- fixed right columns ----
    //
    // Declared before the message so the message can anchor to them: in QML,
    // `anchors.right: X.left` needs X to exist, and declaration order is the only
    // guarantee of that in a flat list of children.
    Label {
        id: actorPid
        anchors { right: parent.right; rightMargin: Theme.space2; verticalCenter: parent.verticalCenter }
        visible: !root.compact && root.pid > 0
        width: 96
        horizontalAlignment: Text.AlignRight
        text: {
            var s = "pid " + root.pid;
            var r = root.event ? (root.event.risk || 0) : 0;
            if (r > 0) s += "  r" + r;
            return s;
        }
        color: root.event && (root.event.risk || 0) >= 500 ? Theme.high : Theme.textFaint
        font { pixelSize: Theme.fontSizeSmall; family: Theme.monoFamily }

        // Clicking the pid is the fastest path into an investigation, so it is a
        // hit target rather than just text.
        TapHandler {
            acceptedButtons: Qt.LeftButton | Qt.RightButton
            onTapped: function(button) {
                if (button === Qt.RightButton) {
                    // File-bearing events (scan verdicts, canary trips) can be
                    // deep-scanned straight from the feed.
                    var p = root.event ? String(root.event.path || "") : "";
                    if (p.length > 0) backend.advancedScan(p);
                    else root.investigateRequested(root.pid);
                    return;
                }
                root.investigateRequested(root.pid);
            }
        }
        ToolTip.visible: pidHover.containsMouse
        ToolTip.text: qsTr("Click to run the full escalation pipeline on pid %1").arg(root.pid)
        ToolTip.delay: 350
        HoverHandler { id: pidHover }
    }

    Label {
        id: target
        anchors { right: actorPid.visible ? actorPid.left : parent.right
                  rightMargin: Theme.space2; verticalCenter: parent.verticalCenter }
        visible: root.showTarget && !root.compact && text.length > 0
        width: 160
        elide: Text.ElideMiddle
        // Elided in the middle: for a path, the filename and the top directory are
        // the informative parts and everything between them is boilerplate.
        text: {
            if (!root.event || !root.event.target) return "";
            var t = root.event.target;
            if (t.path && String(t.path).length > 0) return Theme.elideMiddle(t.path, 34);
            if (t.peer_ip && String(t.peer_ip).length > 0) return t.peer_ip + ":" + (t.peer_port || 0);
            return "";
        }
        color: Theme.textFaint
        font.pixelSize: Theme.fontSizeSmall
        font.family: Theme.monoFamily
    }

    // ---- flexible message column ----
    Label {
        id: message
        anchors {
            left: root.escalated ? escDot.right : sensor.right
            leftMargin: Theme.space2
            right: target.visible ? target.left : (actorPid.visible ? actorPid.left : parent.right)
            rightMargin: Theme.space2
            verticalCenter: parent.verticalCenter
        }
        text: root.event ? String(root.event.message || root.event.kind || "") : ""
        color: root.rank >= 4 ? Theme.text : Theme.textDim
        elide: Text.ElideRight
        font {
            pixelSize: Theme.fontSizeBody
            family: Theme.fontFamily
            weight: root.rank >= 4 ? Theme.weightMedium : Theme.weightRegular
        }

        // Full text on hover. Messages are truncated in the column but the operator
        // routinely needs the whole thing, including the embedded paths.
        ToolTip.visible: msgHover.containsMouse && message.truncated
        ToolTip.text: message.text
        ToolTip.delay: 350
        // Long messages wrap in the tooltip rather than producing a screen-wide
        // single line. Available as ToolTip.wrapMode since Qt 6.5; on older Qt the
        // binding fails silently and the tooltip simply does not wrap.
        // (attached ToolTip has no wrapMode; newlines in the text still break)
        HoverHandler { id: msgHover }
    }

    HoverHandler { id: rowHover }
    TapHandler {
        // Do not steal the pid click.
        gesturePolicy: TapHandler.WithinBounds
        onTapped: root.clicked(root.event)
    }
}
