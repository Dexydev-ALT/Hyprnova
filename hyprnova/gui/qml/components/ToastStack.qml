// SPDX-License-Identifier: Apache-2.0
// HyprNova :: toast stack
//
// Bottom-right transient notices. Four rules drive the design, and each one exists
// because the alternative fails during an incident:
//
//   1. NEVER MODAL. A toast must not be able to interrupt a triage action. That is
//      what ThreatDialog is for; the two are deliberately different objects.
//   2. BOUNDED. At most `maxVisible` rendered and `maxQueued` retained. A busy host
//      can produce dozens of agent actions per second and an unbounded stack would
//      cover the console — the exact failure mode a notification system must not
//      have.
//   3. COALESCED. Identical (severity, message) pairs inside the cooldown increment
//      a counter on the live card. "Blocked 192.0.2.7 (x14)" beats fourteen
//      overlapping cards.
//   4. NOT DISRUPTIVE. New cards enter at the bottom and existing cards do not move
//      or restart their timers. Achieved with a ListView (stable delegate identity)
//      rather than a Repeater, which destroys and rebuilds every delegate on any
//      model change and would visibly flicker the whole stack on each new toast.
//
// Lifetime is per-card: a Timer inside the delegate. No central scheduler, so a
// stack of one card costs the same as a stack of four.

import QtQuick
import QtQuick.Controls
import "../theme"

Item {
    id: root

    /// Maximum cards rendered at once.
    property int maxVisible: 4
    /// Maximum retained (rendered + queued) before the oldest is dropped.
    property int maxQueued: 12
    /// Identical notices inside this window coalesce into one card.
    property int coalesceMs: 1500
    /// Time-to-live. Critical notices stay longer: they are the ones an operator may
    /// need to read twice, and they are rare enough not to clutter.
    property int ttlMs: 5000
    property int ttlCriticalMs: 12000
    property int cardWidth: 340

    /// Live toasts, newest first: {key, severity, message, detail, count, ts}
    property var toasts: []

    signal dismissed(string key)

    function push(severity, message, detail) {
        var sev = String(severity || "info").toLowerCase();
        var msg = String(message || "");
        if (msg.length === 0) return;
        var key = sev + "|" + msg;
        var now = Date.now();

        var next = [];
        var merged = false;
        for (var i = 0; i < toasts.length; ++i) {
            var t = toasts[i];
            if (!merged && t.key === key && (now - t.ts) < coalesceMs) {
                var c = Object.assign({}, t);
                c.count = (t.count || 1) + 1;
                c.ts = now;
                if (detail !== undefined && String(detail).length > 0) c.detail = String(detail);
                next.push(c);
                merged = true;
            } else {
                next.push(t);
            }
        }
        if (!merged) {
            next.unshift({ key: key, severity: sev, message: msg,
                           detail: detail === undefined ? "" : String(detail),
                           count: 1, ts: now });
        }
        while (next.length > maxQueued) next.pop();
        toasts = next;
    }

    function dismiss(key) {
        var next = [];
        for (var i = 0; i < toasts.length; ++i)
            if (toasts[i].key !== key) next.push(toasts[i]);
        if (next.length !== toasts.length) toasts = next;
        dismissed(key);
    }

    function clear() { toasts = []; }

    /// Rendered slice. The rest wait in `toasts` and slide in as older ones expire,
    /// so the array can be larger than the screen without ever drawing more than
    /// `maxVisible` cards.
    readonly property var visibleToasts: toasts.slice(0, maxVisible)

    ListView {
        id: list
        // Anchored by its BOTTOM edge and laid out bottom-to-top, so a new card
        // appears at the bottom and the ones above it stay exactly where they were.
        anchors { right: parent.right; bottom: parent.bottom; margins: Theme.space4 }
        width: root.cardWidth
        height: Math.min(contentHeight, root.parent ? root.parent.height * 0.6 : 400)
        model: root.visibleToasts
        spacing: Theme.space2
        verticalLayoutDirection: ListView.BottomToTop
        interactive: false
        // Deliberately NOT reuseItems: each delegate owns a running TTL timer, and
        // recycling would hand a new toast an expired one's countdown.
        clip: false

        // Enter/leave transitions. ListView applies these per-item on insertion and
        // removal only, which is exactly the granularity we need.
        add: Transition {
            ParallelAnimation {
                NumberAnimation { property: "opacity"; from: 0; to: 1; duration: Theme.animNormal }
                NumberAnimation { property: "x"; from: root.cardWidth * 0.12; to: 0; duration: Theme.animNormal; easing.type: Easing.OutCubic }
            }
        }
        remove: Transition {
            ParallelAnimation {
                NumberAnimation { property: "opacity"; to: 0; duration: Theme.animFast }
                NumberAnimation { property: "x"; to: root.cardWidth * 0.12; duration: Theme.animFast; easing.type: Easing.InCubic }
            }
        }

        delegate: Rectangle {
            id: card

            required property var modelData
            readonly property string key: modelData.key
            readonly property string sev: modelData.severity
            readonly property int count: modelData.count || 1
            readonly property color sevColor: Theme.severityColor(modelData.severity)
            readonly property bool important: sev === "critical" || sev === "high"
            readonly property int ttl: important ? root.ttlCriticalMs : root.ttlMs

            width: ListView.view.width
            height: content.height + Theme.space3 * 2 + 2
            radius: Theme.radiusMd
            color: Theme.raised
            border.width: 1
            border.color: Theme.withAlpha(sevColor, 0.45)

            // Left severity spine: reads faster than a coloured title and survives
            // being glanced at from an angle.
            Rectangle {
                anchors { left: parent.left; top: parent.top; bottom: parent.bottom }
                width: 3
                radius: Theme.radiusMd
                color: card.sevColor
            }

            // Glow ring, reserved for critical/high. Everything else stays flat, so
            // the ring still means something after weeks of use.
            Rectangle {
                anchors.fill: parent
                radius: parent.radius
                color: "transparent"
                border.width: 2
                border.color: Theme.withAlpha(card.sevColor, 0.18)
                visible: card.important

                SequentialAnimation on opacity {
                    running: card.important && card.visible
                    loops: Animation.Infinite
                    NumberAnimation { to: 0.35; duration: Theme.pulseMs / 2; easing.type: Easing.InOutSine }
                    NumberAnimation { to: 1.0;  duration: Theme.pulseMs / 2; easing.type: Easing.InOutSine }
                }
            }

            Column {
                id: content
                anchors {
                    left: parent.left; right: parent.right; top: parent.top
                    leftMargin: Theme.space4; rightMargin: Theme.space3; topMargin: Theme.space3
                }
                spacing: 2

                Row {
                    width: parent.width
                    spacing: Theme.space2

                    Label {
                        text: card.sev.toUpperCase()
                        color: card.sevColor
                        width: parent.width - closeBtn.width - countLabel.width - Theme.space2 * 2
                        font {
                            pixelSize: Theme.fontSizeMicro
                            family: Theme.fontFamily
                            weight: Theme.weightBold
                            letterSpacing: 1.0
                        }
                        verticalAlignment: Text.AlignVCenter
                    }

                    Label {
                        id: countLabel
                        visible: card.count > 1
                        text: "\u00D7" + card.count
                        color: Theme.text
                        font {
                            pixelSize: Theme.fontSizeMicro
                            family: Theme.monoFamily
                            weight: Theme.weightBold
                        }
                        verticalAlignment: Text.AlignVCenter
                    }

                    // Close. Small glyph, generous hit area: toasts get dismissed by
                    // reflex while the operator is reading something else.
                    Label {
                        id: closeBtn
                        text: "\u00D7"
                        color: dismissHover.containsMouse ? Theme.text : Theme.textFaint
                        width: 18
                        horizontalAlignment: Text.AlignHCenter
                        font.pixelSize: Theme.fontSizeLarge
                        verticalAlignment: Text.AlignVCenter

                        HoverHandler { id: dismissHover }
                        TapHandler { onTapped: root.dismiss(card.key) }
                    }
                }

                Label {
                    text: card.modelData.message
                    color: Theme.text
                    width: parent.width
                    wrapMode: Text.WordWrap
                    maximumLineCount: 3
                    elide: Text.ElideRight
                    font {
                        pixelSize: Theme.fontSizeBody
                        family: Theme.fontFamily
                        weight: Theme.weightMedium
                    }
                }

                Label {
                    text: card.modelData.detail
                    visible: (card.modelData.detail || "").length > 0
                    color: Theme.textDim
                    width: parent.width
                    wrapMode: Text.WordWrap
                    maximumLineCount: 2
                    elide: Text.ElideRight
                    font.pixelSize: Theme.fontSizeSmall
                    font.family: Theme.monoFamily
                }
            }

            // Time-to-live bar. The operator can see how much reading time is left,
            // which is the difference between a card that vanishes mid-sentence and
            // one that clearly means to.
            Rectangle {
                id: ttlBar
                anchors { left: parent.left; right: parent.right; bottom: parent.bottom }
                height: 2
                radius: 1
                color: Theme.withAlpha(card.sevColor, 0.65)
                transformOrigin: Item.Left

                NumberAnimation on scale {
                    from: 1.0; to: 0.0
                    duration: card.ttl
                    running: card.visible
                    easing.type: Easing.Linear
                }
            }

            // Pausing the countdown while the pointer is over the card is the single
            // highest-value affordance here: it means reading a notice never races a
            // timer, without adding a "pin" control to learn.
            Timer {
                id: life
                interval: card.ttl
                repeat: false
                running: card.visible && !cardHover.containsMouse
                // Restart rather than resume: hovering resets the clock, so a card
                // being read stays put until the operator moves away.
                onTriggered: root.dismiss(card.key)
            }
            HoverHandler { id: cardHover }
        }
    }
}
