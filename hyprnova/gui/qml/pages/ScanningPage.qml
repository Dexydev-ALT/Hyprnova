// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Scanning
//
// Module 3's console. The page answers: what engine is running, what has it found,
// and what is it doing right now. Three panels:
//
//   COUNTERS   — the cheap summary an operator glances at: scanned, clean,
//                suspicious, malicious, cache hit rate, mean scan time, queue depth.
//   FINDINGS   — the recent verdicts, newest first, with the engine that produced
//                them. A verdict of "unknown" is shown honestly as unknown: the
//                agent would rather say "I do not know" than guess.
//   SWEEP      — when a full sweep is running, its progress and the path it is
//                currently on. A sweep of 500k files takes minutes, and an operator
//                watching a frozen-looking progress bar will kill the agent.
//
// The engine banner is deliberately prominent: an operator must be able to tell
// "YaraLite, in-tree" from "libyara, vendor" from "clamd, streamed" at a glance,
// because each has a different coverage story.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import "../theme"
import "../components"

Item {
    id: page

    readonly property var counters: backend.scanCounters
    readonly property var results: backend.scanResults
    readonly property string engine: {
        var c = page.counters;
        if (c.libyara) return qsTr("libyara (vendor)");
        if (c.clamdscan && c.clamd_socket_alive) return qsTr("clamd streamed");
        if (c.kvrt) return qsTr("KVRT (custom list)");
        return qsTr("YaraLite (in-tree)");
    }
    readonly property bool sweepRunning: counters.sweep_running === true
    readonly property real sweepProgress: {
        var c = page.counters;
        if (!c.sweep_running) return 0;
        // The agent reports sweep_progress 0..1 and sweep_current as the path being
        // scanned. Progress is shown as a fraction; the path is the reassurance.
        return Math.max(0, Math.min(1, Number(c.sweep_progress) || 0));
    }

    Flickable {
        anchors.fill: parent
        contentWidth: width
        contentHeight: col.height + Theme.space5 * 2
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        ColumnLayout {
            id: col
            anchors { left: parent.left; right: parent.right; top: parent.top; margins: Theme.space5 }
            spacing: Theme.space4

            // ---- engine banner ----
            Panel {
                Layout.fillWidth: true
                Layout.preferredHeight: 84
                title: ""
                showAccent: false
                accentColor: Theme.accent

                RowLayout {
                    anchors { fill: parent; margins: Theme.space4 }
                    spacing: Theme.space5

                    GlowDot {
                        size: 14
                        color: page.counters.enabled === false ? Theme.down : Theme.ok
                        glow: true
                        pulse: page.counters.enabled === false
                    }
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 2
                        Label {
                            text: page.engine
                            color: Theme.text
                            font { pixelSize: Theme.fontSizeTitle; family: Theme.fontFamily; weight: Theme.weightBold }
                        }
                        Label {
                            text: page.counters.enabled === false
                                  ? (page.counters.note || qsTr("scanning is disabled in configuration"))
                                  : qsTr("%1 rules \u00B7 %2 patterns \u00B7 backend: %3")
                                        .arg(page.counters.rules || 0)
                                        .arg(page.counters.patterns || 0)
                                        .arg(page.counters.backend || "yara-lite")
                            color: Theme.textDim
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            elide: Text.ElideRight
                            Layout.fillWidth: true
                        }
                    }

                    Rectangle { Layout.preferredWidth: 1; Layout.fillHeight: true; color: Theme.border }

                    // External engines, if any. Each is shown with whether it is
                    // actually reachable: a configured-but-dead clamd is a coverage
                    // gap, not a feature.
                    RowLayout {
                        spacing: Theme.space4
                        Repeater {
                            model: [
                                { name: "clamd",    ok: page.counters.clamd_socket_alive === true, note: page.counters.clamd_socket || "" },
                                { name: "kvrt",     ok: page.counters.kvrt_runnable === true,  note: "kvrt.run" }
                            ]
                            delegate: ColumnLayout {
                                required property var modelData
                                spacing: 2
                                RowLayout {
                                    spacing: Theme.space2
                                    GlowDot {
                                        size: 7
                                        color: modelData.ok ? Theme.ok : Theme.textFaint
                                        glow: modelData.ok
                                    }
                                    Label {
                                        text: modelData.name
                                        color: Theme.textDim
                                        font.pixelSize: Theme.fontSizeSmall
                                        font.family: Theme.monoFamily
                                    }
                                }
                                Label {
                                    text: modelData.ok ? qsTr("live") : qsTr("not reachable")
                                    color: modelData.ok ? Theme.ok : Theme.textFaint
                                    font.pixelSize: Theme.fontSizeMicro
                                    font.family: Theme.monoFamily
                                }
                            }
                        }
                    }

                    Rectangle { Layout.preferredWidth: 1; Layout.fillHeight: true; color: Theme.border }

                    ColumnLayout {
                        spacing: 2
                        Layout.alignment: Qt.AlignVCenter
                        NovaButton {
                            text: qsTr("Full sweep")
                            role: "primary"
                            onTriggered: backend.fullSweep()
                            ToolTip.visible: hovered
                            ToolTip.text: qsTr("Walk the configured roots and scan every file. " +
                                               "Capped at 500k files with periodic yields so the " +
                                               "agent never starves the sensors.")
                        }
                        NovaButton {
                            text: qsTr("Scan a path")
                            role: "secondary"
                            onTriggered: pathDialog.open()
                        }
                    }
                }
            }

            // ---- counters ----
            GridLayout {
                Layout.fillWidth: true
                columns: parent.width >= 1100 ? 6 : (parent.width >= 760 ? 3 : 2)
                rowSpacing: Theme.space4
                columnSpacing: Theme.space4

                StatTile {
                    Layout.fillWidth: true
                    label: qsTr("Scanned")
                    value: page.fmt(page.counters.scanned)
                    hint: qsTr("files hashed and matched")
                }
                StatTile {
                    Layout.fillWidth: true
                    label: qsTr("Clean")
                    value: page.fmt(page.counters.clean)
                    hint: qsTr("no rule matched")
                    valueColor: Theme.ok
                }
                StatTile {
                    Layout.fillWidth: true
                    label: qsTr("Suspicious")
                    value: page.fmt(page.counters.suspicious)
                    hint: qsTr("heuristic hit, not a signature")
                    valueColor: (page.counters.suspicious || 0) > 0 ? Theme.medium : Theme.text
                    alarm: (page.counters.suspicious || 0) > 0
                }
                StatTile {
                    Layout.fillWidth: true
                    label: qsTr("Malicious")
                    value: page.fmt(page.counters.malicious)
                    hint: qsTr("signature match")
                    valueColor: (page.counters.malicious || 0) > 0 ? Theme.critical : Theme.text
                    alarm: (page.counters.malicious || 0) > 0
                }
                StatTile {
                    Layout.fillWidth: true
                    label: qsTr("Cache hits")
                    value: page.counters.cache_hits > 0
                           ? Math.round(100 * page.counters.cache_hits / Math.max(1, page.counters.scanned)) + "%"
                           : "\u2013"
                    hint: qsTr("same sha256+size+mtime as a previous scan")
                }
                StatTile {
                    Layout.fillWidth: true
                    label: qsTr("Mean scan")
                    value: (page.counters.mean_scan_ms || 0).toFixed(1) + " ms"
                    hint: qsTr("queue depth %1").arg(page.counters.queue_depth || 0)
                }
            }

            // ---- sweep progress ----
            Panel {
                visible: page.sweepRunning
                Layout.fillWidth: true
                Layout.preferredHeight: 96
                title: qsTr("Full sweep in progress")
                subtitle: Theme.elideMiddle(page.counters.sweep_current || "", 80)
                glyph: "\u2315"
                accentColor: Theme.accent

                ColumnLayout {
                    anchors { left: parent.left; right: parent.right; bottom: parent.bottom }
                    spacing: Theme.space2

                    ProgressBar {
                        Layout.fillWidth: true
                        Layout.preferredHeight: 6
                        from: 0; to: 1
                        value: page.sweepProgress
                        palette.highlight: Theme.accent
                        palette.dark: Theme.surfaceAlt
                    }
                    Label {
                        text: qsTr("%1% complete").arg(Math.round(page.sweepProgress * 100))
                        color: Theme.textDim
                        font.pixelSize: Theme.fontSizeSmall
                        font.family: Theme.monoFamily
                    }
                }
            }

            // ---- recent findings ----
            Panel {
                Layout.fillWidth: true
                Layout.preferredHeight: 420
                title: qsTr("Recent results")
                subtitle: qsTr("newest first \u00B7 verdict is the engine's, not a guess")
                glyph: "\u2315"
                accentColor: Theme.riskColor((page.counters.malicious || 0) > 0 ? 900 : 0)
                headerRight: Label {
                    text: qsTr("%1 shown").arg(page.results.length)
                    color: Theme.textFaint
                    font.pixelSize: Theme.fontSizeSmall
                    font.family: Theme.monoFamily
                }

                ListView {
                    anchors.fill: parent
                    clip: true
                    model: page.results
                    spacing: 2
                    boundsBehavior: Flickable.StopAtBounds
                    reuseItems: true

                    header: Row {
                        width: parent.width
                        height: 24
                        spacing: Theme.space3
                        Label { text: qsTr("VERDICT"); width: 90; color: Theme.textFaint; font { pixelSize: Theme.fontSizeMicro; weight: Theme.weightBold; letterSpacing: 1.0 } }
                        Label { text: qsTr("PATH"); width: parent.width * 0.42; color: Theme.textFaint; font { pixelSize: Theme.fontSizeMicro; weight: Theme.weightBold; letterSpacing: 1.0 } }
                        Label { text: qsTr("ENGINE"); width: 90; color: Theme.textFaint; font { pixelSize: Theme.fontSizeMicro; weight: Theme.weightBold; letterSpacing: 1.0 } }
                        Label { text: qsTr("SHA-256"); width: parent.width * 0.18; color: Theme.textFaint; font { pixelSize: Theme.fontSizeMicro; weight: Theme.weightBold; letterSpacing: 1.0 } }
                        Label { text: qsTr("RISK"); width: 70; color: Theme.textFaint; font { pixelSize: Theme.fontSizeMicro; weight: Theme.weightBold; letterSpacing: 1.0 } }
                        Label { text: qsTr("SCAN"); width: 70; color: Theme.textFaint; font { pixelSize: Theme.fontSizeMicro; weight: Theme.weightBold; letterSpacing: 1.0 } }
                    }

                    delegate: Rectangle {
                        id: fRow
                        required property var modelData
                        readonly property string verdict: String(modelData.verdict || "clean")
                        readonly property color vColor: Theme.verdictColor(verdict)

                        width: ListView.view.width
                        height: 34
                        radius: Theme.radiusSm
                        color: fHover.containsMouse ? Theme.surfaceAlt : "transparent"
                        // Malicious and suspicious rows get a spine so they are
                        // findable by colour in a long list.
                        Rectangle {
                            anchors { left: parent.left; top: parent.top; bottom: parent.bottom }
                            width: 2; radius: 1
                            color: fRow.vColor
                            opacity: fRow.verdict === "clean" ? 0.25 : 0.9
                        }

                        Row {
                            anchors {
                                left: parent.left; right: parent.right; verticalCenter: parent.verticalCenter
                                leftMargin: Theme.space3; rightMargin: Theme.space3
                            }
                            spacing: Theme.space3

                            SevBadge {
                                text: fRow.verdict
                                verdictStyle: true
                                autoColor: true
                            }
                            Label {
                                text: Theme.elideMiddle(fRow.modelData.path || "", 52)
                                width: parent.width * 0.42
                                color: fRow.verdict === "clean" ? Theme.textDim : Theme.text
                                font.pixelSize: Theme.fontSizeSmall
                                font.family: Theme.monoFamily
                                verticalAlignment: Text.AlignVCenter
                                height: parent.height
                            }
                            Label {
                                text: fRow.modelData.engine || "yara"
                                width: 90
                                color: Theme.textFaint
                                font.pixelSize: Theme.fontSizeSmall
                                font.family: Theme.monoFamily
                                verticalAlignment: Text.AlignVCenter
                                height: parent.height
                            }
                            Label {
                                text: fRow.modelData.sha256 ? String(fRow.modelData.sha256).substring(0, 16) + "\u2026" : "\u2013"
                                width: parent.width * 0.18
                                color: Theme.textFaint
                                font.pixelSize: Theme.fontSizeMicro
                                font.family: Theme.monoFamily
                                verticalAlignment: Text.AlignVCenter
                                height: parent.height
                            }
                            Label {
                                text: fRow.modelData.risk !== undefined ? Math.round(fRow.modelData.risk) : "\u2013"
                                width: 70
                                color: Theme.riskColor(fRow.modelData.risk || 0)
                                font { pixelSize: Theme.fontSizeSmall; family: Theme.monoFamily; weight: Theme.weightBold }
                                verticalAlignment: Text.AlignVCenter
                                height: parent.height
                            }
                            Label {
                                text: fRow.modelData.elapsed_ms !== undefined
                                      ? fRow.modelData.elapsed_ms + "ms" : "\u2013"
                                width: 70
                                color: fRow.modelData.from_cache ? Theme.textFaint : Theme.textDim
                                font.pixelSize: Theme.fontSizeMicro
                                font.family: Theme.monoFamily
                                verticalAlignment: Text.AlignVCenter
                                height: parent.height
                            }
                        }

                        HoverHandler { id: fHover }
                        TapHandler {
                            acceptedButtons: Qt.LeftButton | Qt.RightButton
                            onTapped: function(button) {
                                if (button === Qt.RightButton) {
                                    // Right-click: the full ladder (engine + sha256
                                    // + VirusTotal) on the finding's path.
                                    if (fRow.modelData.path)
                                        backend.advancedScan(fRow.modelData.path);
                                    return;
                                }
                                // A finding is only actionable with its path; open the
                                // quarantine confirm directly for non-clean verdicts.
                                if (fRow.verdict !== "clean" && fRow.modelData.path)
                                    quarantineDialog.path = fRow.modelData.path;
                            }
                            onDoubleTapped: {
                                if (fRow.modelData.path) backend.scanPath(fRow.modelData.path);
                            }
                        }
                        ToolTip.visible: fHover.containsMouse
                        ToolTip.text: {
                            var m = fRow.modelData;
                            var parts = [m.path || "",
                                         qsTr("verdict %1 \u00B7 engine %2").arg(m.verdict || "?").arg(m.engine || "?"),
                                         qsTr("sha256 %1").arg(m.sha256 || "?"),
                                         qsTr("size %1 \u00B7 entropy %2").arg(Theme.formatBytes(m.size || 0)).arg(m.entropy !== undefined ? m.entropy.toFixed(2) : "?")];
                            if (m.detail) parts.push(String(m.detail));
                            if (m.rule) parts.push(qsTr("rule %1 (%2)").arg(m.rule).arg(m.family || ""));
                            return parts.join("\n");
                        }
                        // (attached ToolTip has no wrapMode; newlines in the text still break)
                    }
                }

                EmptyState {
                    anchors.centerIn: parent
                    visible: page.results.length === 0
                    good: true
                    message: qsTr("No scan results yet")
                    hint: qsTr("Run a full sweep, or scan a path, and verdicts appear here.")
                }
            }
        }
    }

    Dialog {
        id: pathDialog
        modal: true
        title: qsTr("Scan a path")
        anchors.centerIn: Overlay.overlay
        width: 420

        background: Rectangle { radius: Theme.radiusMd; color: Theme.surface; border.width: 1; border.color: Theme.border }

        contentItem: ColumnLayout {
            spacing: Theme.space3
            Label {
                text: qsTr("Absolute path to a file or directory. Directories are walked recursively.")
                color: Theme.textDim
                font.pixelSize: Theme.fontSizeSmall
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }
            TextField {
                id: scanPathField
                Layout.fillWidth: true
                placeholderText: "/home/user/Downloads/suspect.bin"
                color: Theme.text
                placeholderTextColor: Theme.textFaint
                font.pixelSize: Theme.fontSizeSmall
                font.family: Theme.monoFamily
                background: Rectangle {
                    radius: Theme.radiusSm
                    color: Theme.surfaceAlt
                    border.width: 1
                    border.color: scanPathField.activeFocus ? Theme.accent : Theme.border
                }
            }
            RowLayout {
                Layout.fillWidth: true
                spacing: Theme.space2
                Item { Layout.fillWidth: true }
                NovaButton {
                    text: qsTr("Cancel")
                    role: "ghost"
                    onTriggered: pathDialog.close()
                }
                NovaButton {
                    text: qsTr("Scan")
                    role: "primary"
                    enabled: scanPathField.text.trim().length > 0
                    onTriggered: {
                        backend.scanPath(scanPathField.text.trim());
                        pathDialog.close();
                    }
                }
            }
        }
    }

    // Quarantine confirm, shared by the findings list.
    Dialog {
        id: quarantineDialog
        property string path: ""
        modal: true
        title: qsTr("Quarantine file")
        anchors.centerIn: Overlay.overlay
        width: 420

        background: Rectangle { radius: Theme.radiusMd; color: Theme.surface; border.width: 1; border.color: Theme.border }

        contentItem: ColumnLayout {
            spacing: Theme.space3
            Label {
                text: qsTr("The file is hashed, moved to quarantine with mode 0400, and its original " +
                           "path is recorded so it can be restored. The process that has it open keeps " +
                           "its file descriptor; nothing is killed by this action.")
                color: Theme.textDim
                font.pixelSize: Theme.fontSizeSmall
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }
            Label {
                text: quarantineDialog.path
                color: Theme.text
                font.pixelSize: Theme.fontSizeSmall
                font.family: Theme.monoFamily
                wrapMode: Text.WrapAnywhere
                Layout.fillWidth: true
            }
            RowLayout {
                Layout.fillWidth: true
                spacing: Theme.space2
                Item { Layout.fillWidth: true }
                NovaButton { text: qsTr("Cancel"); role: "ghost"; onTriggered: quarantineDialog.close() }
                NovaButton {
                    text: qsTr("Quarantine")
                    role: "danger"
                    confirm: true
                    onTriggered: {
                        backend.quarantine(quarantineDialog.path);
                        quarantineDialog.close();
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
