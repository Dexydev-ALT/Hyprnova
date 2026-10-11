// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Canaries
//
// Module 2's console. Canaries are decoy files planted in the places ransomware
// actually touches first — user homes, /tmp, web roots — with real magic bytes
// and an HMAC so a "modified" verdict is cryptographically certain rather than a
// heuristic. This page is the difference between "we think something is wrong"
// and "we can prove file #4,321 was overwritten at 03:14:22 by pid 8841".
//
// Layout: a headline strip (planted / healthy / tampered, with the alarm state),
// then the per-canary table. The table shows entropy, because entropy is the
// signal: a canary overwritten with random bytes (encryption) has entropy near 8.0,
// while the planted decoy has a known, much lower value.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import "../theme"
import "../components"

Item {
    id: page

    readonly property var c: backend.canaries
    readonly property var hp: page.c.honeypots || {}
    readonly property var hpDecoys: page.hp.decoys || []
    readonly property int hpPlanted: page.hp.planted || 0
    readonly property var list: page.c.canaries || []
    readonly property int planted: page.c.planted || 0
    readonly property int healthy: page.c.healthy || 0
    readonly property int tampered: page.c.tampered || 0
    readonly property bool alarm: tampered > 0

    readonly property var tamperedRows: {
        var out = [];
        for (var i = 0; i < page.list.length; ++i) {
            var v = String(page.list[i].verdict || "").toLowerCase();
            if (v === "tampered" || v === "modified" || v === "missing") out.push(page.list[i]);
        }
        return out;
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.space5
        spacing: Theme.space4

        // ---- headline ----
        Panel {
            Layout.fillWidth: true
            Layout.preferredHeight: 110
            title: ""
            showAccent: false
            accentColor: page.alarm ? Theme.critical : Theme.ok

            RowLayout {
                anchors { fill: parent; margins: Theme.space4 }
                spacing: Theme.space5

                GlowDot {
                    size: 16
                    color: page.alarm ? Theme.critical : Theme.ok
                    glow: true
                    pulse: page.alarm
                }
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 2
                    Label {
                        text: page.alarm ? qsTr("CANARY TAMPERING DETECTED") : qsTr("Canaries intact")
                        color: page.alarm ? Theme.critical : Theme.text
                        font { pixelSize: Theme.fontSizeTitle; family: Theme.fontFamily; weight: Theme.weightBold }
                    }
                    Label {
                        text: page.alarm
                              ? qsTr("%1 of %2 canaries have been modified or removed. This is the " +
                                     "earliest and most reliable ransomware indicator the agent has.")
                                    .arg(page.tampered).arg(page.planted)
                              : qsTr("%1 planted \u00B7 %2 healthy \u00B7 fanotify %3")
                                    .arg(page.planted).arg(page.healthy)
                                    .arg(page.c.fanotify ? qsTr("armed") : qsTr("inotify only"))
                        color: Theme.textDim
                        font.pixelSize: Theme.fontSizeSmall
                        Layout.fillWidth: true
                        elide: Text.ElideRight
                    }
                }

                Rectangle { Layout.preferredWidth: 1; Layout.fillHeight: true; color: Theme.border }

                StatTile {
                    label: qsTr("Planted")
                    value: page.planted
                    hint: qsTr("decoys in homes, /tmp, web roots")
                    Layout.preferredWidth: 130
                }
                StatTile {
                    label: qsTr("Healthy")
                    value: page.healthy
                    hint: qsTr("HMAC verified")
                    valueColor: Theme.ok
                    Layout.preferredWidth: 130
                }
                StatTile {
                    label: qsTr("Tampered")
                    value: page.tampered
                    hint: page.alarm ? qsTr("act on this now") : qsTr("none")
                    valueColor: page.alarm ? Theme.critical : Theme.text
                    alarm: page.alarm
                    Layout.preferredWidth: 130
                }

                Rectangle { Layout.preferredWidth: 1; Layout.fillHeight: true; color: Theme.border }

                ColumnLayout {
                    Layout.alignment: Qt.AlignVCenter
                    spacing: Theme.space2
                    NovaButton {
                        text: qsTr("Re-plant all")
                        role: "primary"
                        onTriggered: backend.plantCanaries()
                        ToolTip.visible: hovered
                        ToolTip.text: qsTr("Write fresh decoys with new HMACs. Existing healthy " +
                                           "canaries are left alone; tampered ones are replaced.")
                    }
                    NovaButton {
                        text: qsTr("Re-check all")
                        role: "secondary"
                        onTriggered: backend.refreshCanaries()
                    }
                }
            }
        }

        // ---- tampered first ----
        Panel {
            visible: page.alarm
            Layout.fillWidth: true
            Layout.preferredHeight: 200
            title: qsTr("Tampered canaries")
            subtitle: qsTr("sorted by last check \u2014 these are your IOCs")
            glyph: "\u26A0"
            accentColor: Theme.critical

            ListView {
                anchors.fill: parent
                clip: true
                model: page.tamperedRows
                spacing: 2
                boundsBehavior: Flickable.StopAtBounds

                delegate: Rectangle {
                    required property var modelData
                    width: ListView.view.width
                    height: 36
                    radius: Theme.radiusSm
                    color: Theme.withAlpha(Theme.critical, 0.07)
                    border.width: 1
                    border.color: Theme.withAlpha(Theme.critical, 0.4)

                    RowLayout {
                        anchors { fill: parent; leftMargin: Theme.space3; rightMargin: Theme.space3 }
                        spacing: Theme.space3

                        SevBadge { text: modelData.verdict || "tampered"; solid: true }
                        Label {
                            text: Theme.elideMiddle(modelData.path || "", 60)
                            color: Theme.text
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            elide: Text.ElideMiddle
                            Layout.fillWidth: true
                        }
                        Label {
                            text: qsTr("entropy %1").arg(modelData.entropy !== undefined
                                                       ? Number(modelData.entropy).toFixed(2) : "?")
                            color: (modelData.entropy || 0) > 7.0 ? Theme.critical : Theme.high
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                        }
                        Label {
                            text: Theme.formatClock(modelData.checked_at || 0)
                            color: Theme.textFaint
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                        }
                    }
                }
            }
        }

        // ---- all canaries ----
        Panel {
            Layout.fillWidth: true
            Layout.fillHeight: true
            title: qsTr("All canaries")
            subtitle: qsTr("%1 rows \u00B7 verdict is HMAC-verified, not heuristic").arg(page.list.length)
            glyph: "\u25CE"
            headerRight: RowLayout {
                spacing: Theme.space2
                NovaButton {
                    text: qsTr("Show tampered only")
                    role: showOnlyTampered ? "primary" : "ghost"
                    compact: true
                    property bool showOnlyTampered: false
                    onTriggered: showOnlyTampered = !showOnlyTampered
                }
                NovaButton {
                    text: qsTr("Refresh")
                    role: "ghost"
                    compact: true
                    glyph: "\u21BB"
                    onTriggered: backend.refreshCanaries()
                }
            }

            ListView {
                anchors.fill: parent
                clip: true
                model: page.list
                spacing: 1
                boundsBehavior: Flickable.StopAtBounds
                reuseItems: true

                header: Row {
                    width: parent.width
                    height: 24
                    spacing: Theme.space3
                    Label { text: qsTr("VERDICT"); width: 90; color: Theme.textFaint; font { pixelSize: Theme.fontSizeMicro; weight: Theme.weightBold; letterSpacing: 1.0 } }
                    Label { text: qsTr("PATH"); width: parent.width * 0.46; color: Theme.textFaint; font { pixelSize: Theme.fontSizeMicro; weight: Theme.weightBold; letterSpacing: 1.0 } }
                    Label { text: qsTr("ROOT"); width: 110; color: Theme.textFaint; font { pixelSize: Theme.fontSizeMicro; weight: Theme.weightBold; letterSpacing: 1.0 } }
                    Label { text: qsTr("SIZE"); width: 80; color: Theme.textFaint; font { pixelSize: Theme.fontSizeMicro; weight: Theme.weightBold; letterSpacing: 1.0 } }
                    Label { text: qsTr("ENTROPY"); width: 80; color: Theme.textFaint; font { pixelSize: Theme.fontSizeMicro; weight: Theme.weightBold; letterSpacing: 1.0 } }
                    Label { text: qsTr("CHECKED"); width: 80; color: Theme.textFaint; font { pixelSize: Theme.fontSizeMicro; weight: Theme.weightBold; letterSpacing: 1.0 } }
                }

                delegate: Rectangle {
                    id: cRow
                    required property var modelData
                    readonly property string verdict: String(modelData.verdict || "ok").toLowerCase()
                    readonly property color vColor: {
                        switch (cRow.verdict) {
                        case "ok": return Theme.ok;
                        case "tampered": return Theme.critical;
                        case "modified": return Theme.high;
                        case "missing": return Theme.high;
                        case "unreadable": return Theme.medium;
                        case "malformed": return Theme.medium;
                        default: return Theme.textFaint;
                        }
                    }

                    width: ListView.view.width
                    height: 30
                    radius: Theme.radiusSm
                    color: cHover.containsMouse ? Theme.surfaceAlt : "transparent"
                    Rectangle {
                        anchors { left: parent.left; top: parent.top; bottom: parent.bottom }
                        width: 2; radius: 1; color: cRow.vColor
                        opacity: cRow.verdict === "ok" ? 0.3 : 1.0
                    }

                    Row {
                        anchors { fill: parent; leftMargin: Theme.space3; rightMargin: Theme.space3 }
                        spacing: Theme.space3

                        SevBadge {
                            text: cRow.verdict
                            customColor: cRow.vColor
                            autoColor: false
                        }
                        Label {
                            text: Theme.elideMiddle(cRow.modelData.path || "", 64)
                            width: parent.width * 0.46
                            color: cRow.verdict === "ok" ? Theme.textDim : Theme.text
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            verticalAlignment: Text.AlignVCenter
                            height: parent.height
                        }
                        Label {
                            text: cRow.modelData.root || ""
                            width: 110
                            color: Theme.textFaint
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            elide: Text.ElideRight
                            verticalAlignment: Text.AlignVCenter
                            height: parent.height
                        }
                        Label {
                            text: Theme.formatBytes(cRow.modelData.size || cRow.modelData.bytes || 0)
                            width: 80
                            color: Theme.textFaint
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            verticalAlignment: Text.AlignVCenter
                            height: parent.height
                        }
                        // Entropy bar: a canary is a known-content decoy, so a high
                        // entropy means it has been overwritten with random bytes.
                        Item {
                            width: 80
                            height: parent.height
                            Row {
                                anchors.verticalCenter: parent.verticalCenter
                                spacing: Theme.space1
                                Rectangle {
                                    width: 40
                                    height: 4
                                    radius: 2
                                    color: Theme.surfaceAlt
                                    Rectangle {
                                        width: parent.width * Math.min(1, (cRow.modelData.entropy || 0) / 8)
                                        height: parent.height
                                        radius: 2
                                        color: (cRow.modelData.entropy || 0) > 7.0 ? Theme.critical
                                             : (cRow.modelData.entropy || 0) > 5.0 ? Theme.high : Theme.ok
                                    }
                                }
                                Label {
                                    text: cRow.modelData.entropy !== undefined
                                          ? Number(cRow.modelData.entropy).toFixed(1) : "\u2013"
                                    color: Theme.textDim
                                    font.pixelSize: Theme.fontSizeMicro
                                    font.family: Theme.monoFamily
                                }
                            }
                        }
                        Label {
                            text: cRow.modelData.checked_at ? Theme.formatClock(cRow.modelData.checked_at) : "\u2013"
                            width: 80
                            color: Theme.textFaint
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            verticalAlignment: Text.AlignVCenter
                            height: parent.height
                        }
                    }

                    HoverHandler { id: cHover }
                    ToolTip.visible: cHover.containsMouse
                    ToolTip.text: {
                        var m = cRow.modelData;
                        var parts = [m.path || "",
                                     qsTr("verdict %1 \u00B7 serial %2").arg(m.verdict || "?").arg(m.serial || "?"),
                                     qsTr("planted %1").arg(m.created ? Theme.formatDate(m.created) : "?")];
                        if (m.detail) parts.push(String(m.detail));
                        return parts.join("\n");
                    }
                    // (attached ToolTip has no wrapMode; newlines in the text still break)
                }
            }

            EmptyState {
                anchors.centerIn: parent
                visible: page.list.length === 0
                good: false
                message: qsTr("No canaries planted")
                hint: qsTr("The agent plants decoys in /home/*/.canaries, /tmp and /var/www on start-up. " +
                           "If this is empty the canary sensor has not run or has no writable root.")
                NovaButton {
                    text: qsTr("Plant canaries now")
                    role: "primary"
                    onTriggered: backend.plantCanaries()
                }
            }
        }

        // ---- honeypot decoys (row 11) ----
        // Config-shaped bait under the state dir, watched by inotify. Any read,
        // rewrite or deletion of these files raises a FileCanaryHit in the event
        // feed (Threats page) — this panel shows the trap layout, never the bait.
        Panel {
            Layout.fillWidth: true
            Layout.preferredHeight: 220
            title: qsTr("Honeypot decoy configs")
            subtitle: qsTr("credential-shaped bait under the state dir \u2014 opening one is an incident")
            glyph: "\u{1F480}"
            accentColor: page.hpPlanted > 0 ? Theme.ok : Theme.medium

            headerRight: Label {
                text: qsTr("%1 planted").arg(page.hpPlanted)
                color: Theme.textDim
                font.pixelSize: Theme.fontSizeSmall
                font.family: Theme.monoFamily
            }

            ListView {
                anchors.fill: parent
                clip: true
                model: page.hpDecoys
                spacing: 2
                boundsBehavior: Flickable.StopAtBounds
                reuseItems: true

                delegate: Rectangle {
                    id: hpRow
                    required property var modelData
                    width: ListView.view.width
                    height: 34
                    radius: Theme.radiusSm
                    color: "transparent"
                    border.width: 1
                    border.color: Theme.withAlpha(Theme.ok, 0.22)

                    RowLayout {
                        anchors { fill: parent; leftMargin: Theme.space3; rightMargin: Theme.space3 }
                        spacing: Theme.space3

                        GlowDot { size: 7; color: Theme.ok }

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 0
                            Label {
                                text: hpRow.modelData.rel || ""
                                color: Theme.text
                                font.pixelSize: Theme.fontSizeBody
                                font.family: Theme.monoFamily
                            }
                            Label {
                                text: (hpRow.modelData.root || "") + "  \u00b7  baseline " + (hpRow.modelData.sha256_16 || "")
                                color: Theme.textDim
                                font.pixelSize: Theme.fontSizeSmall
                                elide: Text.ElideRight
                                Layout.fillWidth: true
                            }
                        }

                        Label {
                            text: qsTr("armed")
                            color: Theme.ok
                            font.pixelSize: Theme.fontSizeSmall
                        }
                    }
                }

                EmptyState {
                    anchors.centerIn: parent
                    visible: page.hpDecoys.length === 0
                    message: qsTr("No decoy configs planted")
                    hint: qsTr("The honeypot sensor plants credential-shaped decoys under the state " +
                               "dir at start-up. A reader gets detected here and in the event feed.")
                }
            }
        }

        // ---- listener state ----
        Panel {
            Layout.fillWidth: true
            Layout.preferredHeight: 84
            title: ""
            showAccent: false

            RowLayout {
                anchors { fill: parent; margins: Theme.space4 }
                spacing: Theme.space4

                GlowDot {
                    size: 10
                    color: page.c.fanotify ? Theme.ok : Theme.medium
                    glow: true
                }
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 2
                    Label {
                        text: page.c.fanotify ? qsTr("fanotify armed (permission events)") : qsTr("inotify only")
                        color: Theme.text
                        font { pixelSize: Theme.fontSizeBody; family: Theme.fontFamily; weight: Theme.weightMedium }
                    }
                    Label {
                        text: page.c.fanotify
                              ? qsTr("The agent sees every open before it happens and can deny it. Requires CAP_DAC_READ_SEARCH.")
                              : qsTr("The agent sees opens after the fact and attributes them by pid. " +
                                     "fanotify needs root; this is the degraded mode.")
                        color: Theme.textDim
                        font.pixelSize: Theme.fontSizeSmall
                        Layout.fillWidth: true
                        elide: Text.ElideRight
                    }
                }
                Rectangle { Layout.preferredWidth: 1; Layout.fillHeight: true; color: Theme.border }
                ColumnLayout {
                    spacing: 2
                    Layout.alignment: Qt.AlignVCenter
                    Label {
                        text: qsTr("events seen")
                        color: Theme.textFaint
                        font.pixelSize: Theme.fontSizeMicro
                    }
                    Label {
                        text: page.fmt(page.c.events_seen || 0)
                        color: Theme.text
                        font { pixelSize: Theme.fontSizeTitle; family: Theme.monoFamily; weight: Theme.weightBold }
                    }
                }
            }
        }
    }

    function fmt(n) {
        var v = Number(n) || 0;
        if (v < 10000) return String(v);
        if (v < 1000000) return (v / 1000).toFixed(1) + "k";
        return (v / 1000000).toFixed(2) + "M";
    }
}
