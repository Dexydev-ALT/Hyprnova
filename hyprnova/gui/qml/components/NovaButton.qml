// SPDX-License-Identifier: Apache-2.0
// HyprNova :: button
//
// Four visual roles and no more, because the console has to be readable at a
// glance by someone who has been paged:
//
//   primary    filled accent      — the one action this panel exists for
//   secondary  outlined           — everything else
//   danger     outlined red       — kill, quarantine, block. NEVER filled by
//                                   default: a filled red button invites the click
//                                   that causes the outage.
//   ghost      text only          — close, cancel, refresh
//
// Destructive roles additionally require `confirm: true`, which turns the first
// click into "click again to confirm" for three seconds. That is a cheaper
// guardrail than a modal dialog and does not interrupt a rapid triage flow.

import QtQuick
import QtQuick.Controls
import "../theme"

Button {
    id: root

    /// "primary" | "secondary" | "danger" | "ghost"
    property string role: "secondary"
    /// Small variant for table rows and panel headers.
    property bool compact: false
    /// Require a second click to fire. Used for kill/quarantine/block/unblock.
    property bool confirm: false
    /// Set while an agent action is in flight; the button shows a spinner.
    property bool busy: false
    /// Optional leading glyph.
    property string glyph: ""

    /// The action signal. Use `onTriggered:` in pages, NOT `onClicked:` — when
    /// `confirm` is set the first click is swallowed to arm the two-step, and
    /// `clicked` still fires for it. `triggered` fires exactly once, only when the
    /// action should actually happen.
    signal triggered()

    readonly property bool isDanger: role === "danger"
    readonly property bool isPrimary: role === "primary"
    readonly property bool isGhost: role === "ghost"
    readonly property color baseColor: isDanger ? Theme.critical
                                     : isPrimary ? Theme.accent
                                                 : Theme.textDim

    // Armed == the operator clicked once on a `confirm` button and has not yet
    // confirmed. Disarmed automatically after confirmWindowMs.
    property bool armed: false
    property int confirmWindowMs: 3000

    Timer {
        id: disarm
        interval: root.confirmWindowMs
        onTriggered: root.armed = false
    }

    implicitHeight: root.compact ? 24 : 34
    implicitWidth: Math.max(root.compact ? 60 : 88, contentRow.implicitWidth + Theme.space4 * 2)
    enabled: !root.busy
    focusPolicy: Qt.StrongFocus   // keyboard operators must be able to tab to "Resume"

    background: Rectangle {
        radius: Theme.radiusSm
        color: {
            if (root.isPrimary)
                return root.down ? Qt.darker(Theme.accent, 1.2)
                                 : root.hovered ? Qt.lighter(Theme.accent, 1.12) : Theme.accent;
            if (root.armed) return Theme.withAlpha(Theme.critical, 0.22);
            if (root.down) return Theme.withAlpha(root.baseColor, 0.18);
            if (root.hovered) return Theme.withAlpha(root.baseColor, 0.10);
            return root.isGhost ? "transparent" : Theme.surfaceAlt;
        }
        border.width: root.isPrimary ? 0 : 1
        border.color: {
            if (root.armed) return Theme.critical;
            if (root.visualFocus) return Theme.accent;
            return Theme.withAlpha(root.baseColor, root.isGhost ? 0.0 : 0.30);
        }

        // Armed state gets a draining underline so the operator can see the
        // confirmation window closing without reading a countdown.
        Rectangle {
            anchors { left: parent.left; right: parent.right; bottom: parent.bottom }
            height: 2
            radius: 1
            visible: root.armed
            color: Theme.critical
            scale: root.armed ? 1.0 : 0.0
            transformOrigin: Item.Left

            SequentialAnimation {
                running: root.armed
                onRunningChanged: if (!running) parent.scale = 1.0
                NumberAnimation {
                    target: parent; property: "scale"; from: 1.0; to: 0.0
                    duration: root.confirmWindowMs; easing.type: Easing.Linear
                }
            }
        }

        Behavior on color { ColorAnimation { duration: Theme.animFast } }
    }

    contentItem: Row {
        id: contentRow
        spacing: Theme.space2
        anchors.centerIn: parent

        // Spinner, shown instead of the icon while busy.
        BusyIndicator {
            visible: root.busy
            running: root.busy
            width: Theme.fontSizeBody
            height: width
            anchors.verticalCenter: parent.verticalCenter
            palette.dark: root.isPrimary ? Theme.textOnAccent : root.baseColor
        }

        Label {
            text: root.glyph
            visible: root.glyph.length > 0 && !root.busy
            color: root.isPrimary ? Theme.textOnAccent : root.baseColor
            font.pixelSize: root.compact ? Theme.fontSizeSmall : Theme.fontSizeBody
            anchors.verticalCenter: parent.verticalCenter
        }

        Label {
            // An armed confirm button says what the second click will do. This is
            // the whole point of the two-step: no operator ever confirms by
            // reflex without reading a verb.
            text: root.armed ? qsTr("Confirm %1").arg(root.text) : root.text
            color: root.isPrimary ? Theme.textOnAccent
                                  : root.armed ? Theme.critical : (root.isGhost && !root.hovered ? Theme.textDim : Theme.text)
            font {
                pixelSize: root.compact ? Theme.fontSizeSmall : Theme.fontSizeBody
                family: Theme.fontFamily
                weight: root.isPrimary ? Theme.weightBold : Theme.weightMedium
                letterSpacing: 0.2
            }
            anchors.verticalCenter: parent.verticalCenter
            elide: Text.ElideRight
        }
    }

    onClicked: {
        if (root.confirm && !root.armed) {
            // Swallow the first click and open the confirmation window, so an
            // accidental click on "Kill" can never reach the agent.
            root.armed = true;
            disarm.restart();
            return;
        }
        root.armed = false;
        disarm.stop();
        root.triggered();
    }

    // Enter and Return route through the same handler, so there is no keyboard
    // path that bypasses the confirmation window either.
    Keys.onReturnPressed: root.clicked()
    Keys.onEnterPressed: root.clicked()
}
