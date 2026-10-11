// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Network
//
// Three panels that answer three different questions:
//
//   LISTENERS    — who is reachable from outside? A listener bound to 0.0.0.0 owned
//                  by an unexpected uid is the single most common initial-access
//                  finding on a compromised Linux box.
//   CONNECTIONS  — what is this host talking to right now? Attributed to a pid via
//                  the inode map, because a destination IP alone does not tell you
//                  which process is responsible.
//   BEACONS      — which connections look like C2? Regular interval + low jitter +
//                  small payloads is the shape of a beacon, and the agent scores it.
//
// Plus the agent's own nftables blocks, with their remaining TTL, because "what
// has the agent already cut off" belongs on the same page as "what is talking".
//
// Sorting is done in the model functions, not in the delegates: a ListView that
// re-sorts by mutating the model re-creates every delegate, which is the visible
// stutter this page exists to avoid.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import "../theme"
import "../components"

Item {
    id: page

    /// "listeners" | "connections" | "beacons" | "blocks"
    property string tab: "beacons"

    readonly property var listeners: backend.listeners
    readonly property var connections: backend.connections
    readonly property var beacons: backend.beacons
    readonly property var blocks: backend.blocks
    readonly property var exeBlocks: backend.exeBlocks || []

    /// Split an "ip:port" socket string into its address part. The bridge emits
    /// local/remote as a single "address:port" string (matching /proc/net), not as
    /// separate fields, so the address has to be peeled off the right-hand side.
    /// IPv6 literals contain colons themselves, so split on the LAST colon.
    function addrOf(socketStr) {
        var t = String(socketStr || "");
        var i = t.lastIndexOf(":");
        return i > 0 ? t.substring(0, i) : t;
    }

    readonly property var externalListeners: {
        // A listener not bound to loopback is reachable from outside. Loopback-only
        // listeners are hidden here (they are in the raw snapshot if ever needed).
        var out = [];
        for (var i = 0; i < page.listeners.length; ++i) {
            var l = page.listeners[i];
            var ip = page.addrOf(l.local);
            if (ip === "127.0.0.1" || ip === "::1" || ip === "localhost" || ip === "") continue;
            out.push(l);
        }
        out.sort(function(a, b) {
            return page.addrOf(b.local).localeCompare(page.addrOf(a.local));
        });
        return out;
    }

    readonly property var outbound: {
        var out = [];
        for (var i = 0; i < page.connections.length; ++i) {
            var c = page.connections[i];
            var st = String(c.state || "");
            // ESTABLISHED and SYN_SENT are the outbound-looking states worth showing.
            if (st === "ESTABLISHED" || st === "SYN_SENT") out.push(c);
        }
        out.sort(function(a, b) { return String(b.remote || "").localeCompare(String(a.remote || "")); });
        return out;
    }

    readonly property var sortedBeacons: {
        var out = page.beacons.slice();
        out.sort(function(a, b) { return (b.score || 0) - (a.score || 0); });
        return out;
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.space5
        spacing: Theme.space4

        // ---- header row: tab chips + block action ----
        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.space3

            RowLayout {
                spacing: Theme.space1
                Repeater {
                    model: [
                        { id: "beacons",     label: qsTr("BEACONS"),     count: page.beacons.length },
                        { id: "listeners",   label: qsTr("LISTENERS"),   count: page.externalListeners.length },
                        { id: "connections", label: qsTr("CONNECTIONS"), count: page.outbound.length },
                        { id: "blocks",      label: qsTr("BLOCKS"),      count: page.blocks.length }
                    ]
                    delegate: NovaButton {
                        required property var modelData
                        text: modelData.label + (modelData.count > 0 ? "  " + modelData.count : "")
                        role: page.tab === modelData.id ? "primary" : "ghost"
                        compact: true
                        Layout.preferredWidth: 110
                        onTriggered: page.tab = modelData.id
                    }
                }
            }

            Item { Layout.fillWidth: true }

            // Manual block. Two-step confirm via NovaButton.
            RowLayout {
                spacing: Theme.space2
                TextField {
                    id: blockIp
                    Layout.preferredWidth: 160
                    placeholderText: qsTr("IP to block")
                    color: Theme.text
                    placeholderTextColor: Theme.textFaint
                    font.pixelSize: Theme.fontSizeSmall
                    font.family: Theme.monoFamily
                    background: Rectangle {
                        radius: Theme.radiusSm
                        color: Theme.surfaceAlt
                        border.width: 1
                        border.color: blockIp.activeFocus ? Theme.accent : Theme.border
                    }
                }
                TextField {
                    id: blockPort
                    Layout.preferredWidth: 64
                    placeholderText: qsTr("port")
                    text: "0"
                    color: Theme.text
                    placeholderTextColor: Theme.textFaint
                    font.pixelSize: Theme.fontSizeSmall
                    font.family: Theme.monoFamily
                    background: Rectangle {
                        radius: Theme.radiusSm
                        color: Theme.surfaceAlt
                        border.width: 1
                        border.color: blockPort.activeFocus ? Theme.accent : Theme.border
                    }
                }
                TextField {
                    id: blockTtl
                    Layout.preferredWidth: 72
                    placeholderText: qsTr("ttl s")
                    text: "3600"
                    color: Theme.text
                    placeholderTextColor: Theme.textFaint
                    font.pixelSize: Theme.fontSizeSmall
                    font.family: Theme.monoFamily
                    background: Rectangle {
                        radius: Theme.radiusSm
                        color: Theme.surfaceAlt
                        border.width: 1
                        border.color: blockTtl.activeFocus ? Theme.accent : Theme.border
                    }
                }
                NovaButton {
                    text: qsTr("Block")
                    role: "danger"
                    confirm: true
                    onTriggered: {
                        var ip = blockIp.text.trim();
                        var port = parseInt(blockPort.text, 10) || 0;
                        var ttl = parseInt(blockTtl.text, 10) || 3600;
                        if (ip.length > 0) backend.block(ip, port, ttl);
                    }
                }
            }
        }

        // ================= BEACONS ========================================
        Panel {
            visible: page.tab === "beacons"
            Layout.fillWidth: true
            Layout.fillHeight: true
            title: qsTr("Beacon candidates")
            subtitle: qsTr("regular interval + low jitter + small payloads = C2 shape")
            glyph: "\u21C4"
            accentColor: page.sortedBeacons.length > 0 ? Theme.high : Theme.ok

            ListView {
                anchors.fill: parent
                clip: true
                model: page.sortedBeacons
                spacing: 3
                boundsBehavior: Flickable.StopAtBounds
                reuseItems: true

                header: Row {
                    width: parent.width
                    height: 24
                    spacing: Theme.space3
                    Label { text: qsTr("DESTINATION"); width: parent.width * 0.18; color: Theme.textFaint; font { pixelSize: Theme.fontSizeMicro; weight: Theme.weightBold; letterSpacing: 1.0 } }
                    Label { text: qsTr("PROCESS"); width: parent.width * 0.20; color: Theme.textFaint; font { pixelSize: Theme.fontSizeMicro; weight: Theme.weightBold; letterSpacing: 1.0 } }
                    Label { text: qsTr("INTERVAL"); width: parent.width * 0.12; color: Theme.textFaint; font { pixelSize: Theme.fontSizeMicro; weight: Theme.weightBold; letterSpacing: 1.0 } }
                    Label { text: qsTr("JITTER"); width: parent.width * 0.10; color: Theme.textFaint; font { pixelSize: Theme.fontSizeMicro; weight: Theme.weightBold; letterSpacing: 1.0 } }
                    Label { text: qsTr("PAYLOAD"); width: parent.width * 0.12; color: Theme.textFaint; font { pixelSize: Theme.fontSizeMicro; weight: Theme.weightBold; letterSpacing: 1.0 } }
                    Label { text: qsTr("SCORE"); width: parent.width * 0.26; color: Theme.textFaint; font { pixelSize: Theme.fontSizeMicro; weight: Theme.weightBold; letterSpacing: 1.0 } }
                }

                delegate: Rectangle {
                    id: bRow
                    required property var modelData
                    readonly property real score: modelData.score || 0
                    readonly property bool beaconLike: modelData.beacon_like === true

                    width: ListView.view.width
                    height: 40
                    radius: Theme.radiusSm
                    color: bHover.containsMouse ? Theme.surfaceAlt : "transparent"
                    border.width: bRow.beaconLike ? 1 : 0
                    border.color: Theme.withAlpha(Theme.high, 0.45)

                    Row {
                        anchors { fill: parent; leftMargin: Theme.space3; rightMargin: Theme.space3 }
                        spacing: Theme.space3

                        Label {
                            // `peer` is "ip:port" already, straight from the EVE
                            // flow record.
                            text: bRow.modelData.peer || "?"
                            width: parent.width * 0.18
                            color: Theme.text
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            elide: Text.ElideRight
                            verticalAlignment: Text.AlignVCenter
                            height: parent.height
                        }
                        Label {
                            // `process` is the comm the beacon was attributed to.
                            text: bRow.modelData.process || "?"
                            width: parent.width * 0.20
                            color: Theme.textDim
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            elide: Text.ElideRight
                            verticalAlignment: Text.AlignVCenter
                            height: parent.height
                        }
                        Label {
                            text: (bRow.modelData.mean_interval || 0).toFixed(1) + "s"
                            width: parent.width * 0.12
                            color: Theme.textDim
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            verticalAlignment: Text.AlignVCenter
                            height: parent.height
                        }
                        Label {
                            text: (bRow.modelData.jitter || 0).toFixed(2)
                            width: parent.width * 0.10
                            color: (bRow.modelData.jitter || 0) < 0.15 ? Theme.high : Theme.textDim
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            verticalAlignment: Text.AlignVCenter
                            height: parent.height
                        }
                        Label {
                            text: Theme.formatBytes((bRow.modelData.bytes_out || 0) + "/" + (bRow.modelData.bytes_in || 0))
                            width: parent.width * 0.12
                            color: Theme.textDim
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            verticalAlignment: Text.AlignVCenter
                            height: parent.height
                        }
                        Item {
                            width: parent.width * 0.26
                            height: parent.height
                            RiskBar {
                                risk: bRow.score * 1000
                                showValue: true
                                compact: true
                                anchors { left: parent.left; right: parent.right; verticalCenter: parent.verticalCenter }
                                thresholds: [0.5, 0.75, 0.85]
                                glowFrom: 0.5
                            }
                        }
                    }

                    HoverHandler { id: bHover }
                    TapHandler {
                        acceptedButtons: Qt.LeftButton | Qt.RightButton
                        onLongPressed: blockMenu.openFor(page.addrOf(bRow.modelData.peer))
                    }
                    ToolTip.visible: bHover.containsMouse
                    ToolTip.text: qsTr("%1 hits \u00B7 interval %2s \u00B7 jitter %3 \u00B7 score %4 \u00B7 %5")
                                  .arg(bRow.modelData.hits || 0)
                                  .arg((bRow.modelData.mean_interval || 0).toFixed(1))
                                  .arg((bRow.modelData.jitter || 0).toFixed(2))
                                  .arg(Math.round(bRow.score * 100) / 100)
                                  .arg(bRow.beaconLike ? qsTr("beacon-like") : qsTr("not beacon-like"))
                }
            }

            EmptyState {
                anchors.centerIn: parent
                visible: page.sortedBeacons.length === 0
                good: true
                message: qsTr("No beacon-shaped traffic")
                hint: qsTr("Beacons are scored on interval regularity, jitter and payload size. " +
                           "A busy but irregular host produces none.")
            }
        }

        // ================= LISTENERS ======================================
        Panel {
            visible: page.tab === "listeners"
            Layout.fillWidth: true
            Layout.fillHeight: true
            title: qsTr("Listening sockets")
            subtitle: qsTr("loopback-only listeners are hidden \u2014 toggle in Settings")
            glyph: "\u25A0"
            accentColor: Theme.medium

            ListView {
                anchors.fill: parent
                clip: true
                model: page.externalListeners
                spacing: 2
                boundsBehavior: Flickable.StopAtBounds
                reuseItems: true

                delegate: Rectangle {
                    id: lRow
                    required property var modelData
                    width: ListView.view.width
                    height: 36
                    radius: Theme.radiusSm
                    color: lHover.containsMouse ? Theme.surfaceAlt : "transparent"

                    Row {
                        anchors { fill: parent; leftMargin: Theme.space3; rightMargin: Theme.space3 }
                        spacing: Theme.space3

                        GlowDot {
                            size: 8
                            color: lRow.modelData.uid === 0 ? Theme.medium : Theme.ok
                            glow: lRow.modelData.uid === 0
                            anchors.verticalCenter: parent.verticalCenter
                        }
                        Label {
                            text: lRow.modelData.local || "?"
                            width: parent.width * 0.22
                            color: Theme.text
                            font.pixelSize: Theme.fontSizeBody
                            font.family: Theme.monoFamily
                            verticalAlignment: Text.AlignVCenter
                            height: parent.height
                        }
                        Label {
                            text: Theme.baseName(lRow.modelData.exe || "") || "?"
                            width: parent.width * 0.24
                            color: Theme.textDim
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            elide: Text.ElideRight
                            verticalAlignment: Text.AlignVCenter
                            height: parent.height
                        }
                        Label {
                            text: "pid " + (lRow.modelData.pid || "?")
                            width: parent.width * 0.12
                            color: Theme.textFaint
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            verticalAlignment: Text.AlignVCenter
                            height: parent.height
                        }
                        Label {
                            text: "uid " + (lRow.modelData.uid !== undefined ? lRow.modelData.uid : "?")
                            width: parent.width * 0.08
                            color: lRow.modelData.uid === 0 ? Theme.medium : Theme.textFaint
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            verticalAlignment: Text.AlignVCenter
                            height: parent.height
                        }
                        Label {
                            text: lRow.modelData.comm || ""
                            width: parent.width * 0.20
                            color: Theme.textDim
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            elide: Text.ElideRight
                            verticalAlignment: Text.AlignVCenter
                            height: parent.height
                        }
                        Item { width: parent.width * 0.14; height: parent.height }
                    }

                    HoverHandler { id: lHover }
                    TapHandler {
                        onTapped: {
                            // Jump to the Processes page; the operator can find the
                            // pid there by filtering. (The listener row carries a pid
                            // but the tree is where lineage is visible.)
                            if (lRow.modelData.pid) Window.window.goTo(2);
                        }
                        onLongPressed: blockMenu.openFor(page.addrOf(lRow.modelData.local))
                    }
                    ToolTip.visible: lHover.containsMouse
                    ToolTip.text: qsTr("inode %1 \u00B7 %2")
                                  .arg(lRow.modelData.inode || "?")
                                  .arg(lRow.modelData.attributed ? qsTr("attributed to a pid") : qsTr("no owning pid found (kernel or other namespace)"))
                }
            }

            EmptyState {
                anchors.centerIn: parent
                visible: page.externalListeners.length === 0
                good: true
                message: qsTr("No externally-reachable listeners")
                hint: qsTr("Only loopback sockets are bound. Good.")
            }
        }

        // ================= CONNECTIONS ====================================
        Panel {
            visible: page.tab === "connections"
            Layout.fillWidth: true
            Layout.fillHeight: true
            title: qsTr("Active connections")
            subtitle: qsTr("ESTABLISHED and SYN_SENT, attributed to a pid")
            glyph: "\u21C4"
            ListView {
                anchors.fill: parent
                clip: true
                model: page.outbound
                spacing: 2
                boundsBehavior: Flickable.StopAtBounds
                reuseItems: true

                delegate: Rectangle {
                    id: cRow
                    required property var modelData
                    width: ListView.view.width
                    height: 34
                    radius: Theme.radiusSm
                    color: cHover.containsMouse ? Theme.surfaceAlt : "transparent"

                    Row {
                        anchors { fill: parent; leftMargin: Theme.space3; rightMargin: Theme.space3 }
                        spacing: Theme.space3

                        Label {
                            text: cRow.modelData.remote || "?"
                            width: parent.width * 0.24
                            color: Theme.text
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            elide: Text.ElideRight
                            verticalAlignment: Text.AlignVCenter
                            height: parent.height
                        }
                        Label {
                            text: String(cRow.modelData.state || "")
                            width: parent.width * 0.12
                            color: cRow.modelData.state === "SYN_SENT" ? Theme.medium : Theme.textDim
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            verticalAlignment: Text.AlignVCenter
                            height: parent.height
                        }
                        Label {
                            text: Theme.baseName(cRow.modelData.exe || "") || "?"
                            width: parent.width * 0.22
                            color: Theme.textDim
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            elide: Text.ElideRight
                            verticalAlignment: Text.AlignVCenter
                            height: parent.height
                        }
                        Label {
                            text: "pid " + (cRow.modelData.pid || "?")
                            width: parent.width * 0.12
                            color: Theme.textFaint
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            verticalAlignment: Text.AlignVCenter
                            height: parent.height
                        }
                        Label {
                            text: cRow.modelData.local || ""
                            width: parent.width * 0.30
                            color: Theme.textFaint
                            font.pixelSize: Theme.fontSizeMicro
                            font.family: Theme.monoFamily
                            elide: Text.ElideRight
                            verticalAlignment: Text.AlignVCenter
                            height: parent.height
                        }
                    }

                    HoverHandler { id: cHover }
                    TapHandler {
                        onTapped: { if (cRow.modelData.pid) backend.investigate(cRow.modelData.pid); }
                        onLongPressed: blockMenu.openFor(page.addrOf(cRow.modelData.remote))
                    }
                }
            }

            EmptyState {
                anchors.centerIn: parent
                visible: page.outbound.length === 0
                good: true
                message: qsTr("No outbound connections")
                hint: qsTr("Nothing on this host has an established or pending outbound socket.")
            }
        }

        // ================= BLOCKS =========================================
        Panel {
            visible: page.tab === "blocks"
            Layout.fillWidth: true
            Layout.fillHeight: true
            title: qsTr("Enforced blocks")
            subtitle: qsTr("nftables rules the agent is holding, with remaining TTL")
            glyph: "\u29B8"
            accentColor: page.blocks.length > 0 ? Theme.high : Theme.ok
            headerRight: Label {
                text: qsTr("%1 active").arg(page.blocks.length)
                color: Theme.textDim
                font.pixelSize: Theme.fontSizeSmall
                font.family: Theme.monoFamily
            }

            ListView {
                anchors.fill: parent
                clip: true
                model: page.blocks
                spacing: 2
                boundsBehavior: Flickable.StopAtBounds
                reuseItems: true

                delegate: Rectangle {
                    id: blRow
                    required property var modelData
                    width: ListView.view.width
                    height: 40
                    radius: Theme.radiusSm
                    color: blHover.containsMouse ? Theme.surfaceAlt : "transparent"
                    border.width: 1
                    border.color: Theme.withAlpha(Theme.high, 0.35)

                    RowLayout {
                        anchors { fill: parent; leftMargin: Theme.space3; rightMargin: Theme.space3 }
                        spacing: Theme.space3

                        GlowDot { size: 8; color: Theme.high; glow: true }

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 0
                            Label {
                                text: blRow.modelData.ip + (blRow.modelData.port ? ":" + blRow.modelData.port : " (all ports)")
                                color: Theme.text
                                font.pixelSize: Theme.fontSizeBody
                                font.family: Theme.monoFamily
                            }
                            Label {
                                text: blRow.modelData.reason || blRow.modelData.desc || ""
                                color: Theme.textDim
                                font.pixelSize: Theme.fontSizeSmall
                                elide: Text.ElideRight
                                Layout.fillWidth: true
                            }
                        }

                        Label {
                            text: page.ttlRemaining(blRow.modelData.installed, blRow.modelData.ttl_seconds)
                            color: Theme.medium
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                        }

                        NovaButton {
                            text: qsTr("Unblock")
                            role: "danger"
                            confirm: true
                            compact: true
                            onTriggered: backend.unblock(blRow.modelData.id !== undefined
                                                          ? blRow.modelData.id : 0)
                        }
                    }

                    HoverHandler { id: blHover }
                }
            }

            EmptyState {
                anchors.centerIn: parent
                visible: page.blocks.length === 0
                good: true
                message: qsTr("No blocks in force")
                hint: qsTr("Blocks appear here when the agent or you cut off a destination. " +
                           "They are TTL-bounded and flushed on shutdown.")
            }
        }

        // ---- per-executable containment (row 12) --------------------------
        // A whole binary (its pid tree, present and future children) moved into
        // a cgroup whose sockets nftables drops. Unfrozen on purpose: the actor
        // stays observable for forensics while it has no network at all.
        Panel {
            visible: page.tab === "blocks"
            Layout.fillWidth: true
            Layout.preferredHeight: Math.min(260, 90 + page.exeBlocks.length * 44)
            title: qsTr("Network-contained executables")
            subtitle: qsTr("whole binaries offline via cgroup v2 + nftables \u2014 the process stays visible, its sockets do not")
            glyph: "\u26D4"
            accentColor: page.exeBlocks.length > 0 ? Theme.critical : Theme.ok
            headerRight: Label {
                text: qsTr("%1 contained").arg(page.exeBlocks.length)
                color: Theme.textDim
                font.pixelSize: Theme.fontSizeSmall
                font.family: Theme.monoFamily
            }

            ListView {
                anchors.fill: parent
                clip: true
                model: page.exeBlocks
                spacing: 2
                boundsBehavior: Flickable.StopAtBounds
                reuseItems: true

                delegate: Rectangle {
                    id: exRow
                    required property var modelData
                    width: ListView.view.width
                    height: 44
                    radius: Theme.radiusSm
                    color: exHover.containsMouse ? Theme.surfaceAlt : "transparent"
                    border.width: 1
                    border.color: Theme.withAlpha(Theme.critical, 0.35)

                    RowLayout {
                        anchors { fill: parent; leftMargin: Theme.space3; rightMargin: Theme.space3 }
                        spacing: Theme.space3

                        GlowDot { size: 8; color: Theme.critical; glow: true }

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 0
                            Label {
                                text: exRow.modelData.exe || ""
                                color: Theme.text
                                font.pixelSize: Theme.fontSizeBody
                                font.family: Theme.monoFamily
                                elide: Text.ElideMiddle
                                Layout.fillWidth: true
                            }
                            Label {
                                text: qsTr("%1 task(s) contained \u00b7 %2").arg(exRow.modelData.tasks || 0).arg(exRow.modelData.reason || "")
                                color: Theme.textDim
                                font.pixelSize: Theme.fontSizeSmall
                                elide: Text.ElideRight
                                Layout.fillWidth: true
                            }
                        }

                        Label {
                            text: page.ttlRemaining(exRow.modelData.installed, exRow.modelData.ttl)
                            color: Theme.medium
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                        }

                        NovaButton {
                            text: qsTr("Release")
                            role: "danger"
                            confirm: true
                            compact: true
                            onTriggered: backend.unblockExe(exRow.modelData.id !== undefined
                                                            ? exRow.modelData.id : 0)
                        }
                    }

                    HoverHandler { id: exHover }
                }
            }

            EmptyState {
                anchors.centerIn: parent
                visible: page.exeBlocks.length === 0
                good: true
                message: qsTr("No executables contained")
                hint: qsTr("Contain one from a threat decision or hyprnova-cli block-exe PID. " +
                           "Needs cgroup v2 + nftables; the agent says so honestly otherwise.")
            }
        }
    }

    Menu {
        id: blockMenu
        property string targetIp: ""
        function openFor(ip) { targetIp = ip || ""; popup(); }
        MenuItem {
            text: qsTr("Block this destination")
            enabled: blockMenu.targetIp.length > 0
            onTriggered: {
                blockIp.text = blockMenu.targetIp;
                page.tab = "blocks";
            }
        }
    }

    /// Seconds remaining on a TTL-bounded block, counting down live.
    function ttlRemaining(installedEpoch, ttlSeconds) {
        if (!installedEpoch || !ttlSeconds) return qsTr("permanent");
        var left = Math.max(0, Math.floor(Number(installedEpoch) + Number(ttlSeconds) - Date.now() / 1000));
        if (left <= 0) return qsTr("expiring");
        if (left < 60) return left + "s";
        if (left < 3600) return Math.floor(left / 60) + "m";
        return Math.floor(left / 3600) + "h " + Math.floor((left % 3600) / 60) + "m";
    }
}
