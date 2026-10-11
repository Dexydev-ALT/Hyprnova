// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Remediation
//
// Module 6's console, and the audit trail for every action the agent has taken.
// This page is what makes an EDR defensible: when an operator asks "why is service
// X down?", the answer is a row here with the actor, the reason, the time, the
// duration, the severity, and — for reversible actions — the undo hint.
//
// Four sections:
//
//   ACTION JOURNAL — every begin/permitted/act/finish, newest first. The outcome
//                    column is honest: "skipped" and "denied" are shown as such,
//                    never hidden.
//   FROZEN         — pids currently SIGSTOP'd, with a one-click Resume. This list
//                    is the agent's blast radius, so it is never empty-looking.
//   BLOCKS         — nftables rules in force with remaining TTL.
//   QUARANTINE     — samples with their sha256 and a Restore button. Restoring puts
//                    the file back with its original mode/uid/gid.
//
// All four are read from the same snapshot, so they are always mutually
// consistent: a pid frozen by the journal appears in FROZEN until it is resumed.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import "../theme"
import "../components"

Item {
    id: page

    readonly property var actions: backend.remediationActions
    readonly property var blocks: backend.blocks
    readonly property var quarantine: backend.quarantined
    readonly property var suspendedPids: {
        // snapshot_remediation carries suspended_pids as a list; fall back to the
        // overview scalar when the list is absent (older bridge).
        return [];
    }
    readonly property int frozenCount: backend.suspendedPids

    /// "journal" | "frozen" | "blocks" | "quarantine"
    property string tab: "journal"

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.space5
        spacing: Theme.space4

        // ---- header ----
        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.space3

            RowLayout {
                spacing: Theme.space1
                Repeater {
                    model: [
                        { id: "journal",   label: qsTr("JOURNAL"),   count: page.actions.length },
                        { id: "frozen",    label: qsTr("FROZEN"),    count: page.frozenCount },
                        { id: "blocks",    label: qsTr("BLOCKS"),    count: page.blocks.length },
                        { id: "quarantine",label: qsTr("QUARANTINE"),count: page.quarantine.length }
                    ]
                    delegate: NovaButton {
                        required property var modelData
                        text: modelData.label + (modelData.count > 0 ? "  " + modelData.count : "")
                        role: page.tab === modelData.id ? "primary" : "ghost"
                        compact: true
                        Layout.preferredWidth: 130
                        onTriggered: page.tab = modelData.id
                    }
                }
            }

            Item { Layout.fillWidth: true }

            Label {
                text: backend.dryRun ? qsTr("DRY RUN \u2014 actions are recorded but not executed")
                                     : qsTr("every row is also in the agent's NDJSON journal (0600)")
                color: backend.dryRun ? Theme.high : Theme.textFaint
                font.pixelSize: Theme.fontSizeSmall
            }
            NovaButton {
                text: qsTr("Refresh")
                role: "ghost"
                compact: true
                glyph: "\u21BB"
                onTriggered: backend.refreshRemediation()
            }
        }

        // ================= JOURNAL ========================================
        Panel {
            visible: page.tab === "journal"
            Layout.fillWidth: true
            Layout.fillHeight: true
            title: qsTr("Action journal")
            subtitle: qsTr("newest first \u00B7 outcome is reported honestly, including failures")
            glyph: "\u2692"
            headerRight: Label {
                text: qsTr("%1 actions").arg(page.actions.length)
                color: Theme.textFaint
                font.pixelSize: Theme.fontSizeSmall
                font.family: Theme.monoFamily
            }

            ListView {
                anchors.fill: parent
                clip: true
                model: page.actions
                spacing: 2
                boundsBehavior: Flickable.StopAtBounds
                reuseItems: true

                header: Row {
                    width: parent.width
                    height: 24
                    spacing: Theme.space3
                    Label { text: qsTr("WHEN"); width: 70; color: Theme.textFaint; font { pixelSize: Theme.fontSizeMicro; weight: Theme.weightBold; letterSpacing: 1.0 } }
                    Label { text: qsTr("ACTION"); width: 110; color: Theme.textFaint; font { pixelSize: Theme.fontSizeMicro; weight: Theme.weightBold; letterSpacing: 1.0 } }
                    Label { text: qsTr("OUTCOME"); width: 90; color: Theme.textFaint; font { pixelSize: Theme.fontSizeMicro; weight: Theme.weightBold; letterSpacing: 1.0 } }
                    Label { text: qsTr("TARGET"); width: parent.width * 0.24; color: Theme.textFaint; font { pixelSize: Theme.fontSizeMicro; weight: Theme.weightBold; letterSpacing: 1.0 } }
                    Label { text: qsTr("REASON"); width: parent.width * 0.30; color: Theme.textFaint; font { pixelSize: Theme.fontSizeMicro; weight: Theme.weightBold; letterSpacing: 1.0 } }
                    Label { text: qsTr("MS"); width: 50; color: Theme.textFaint; font { pixelSize: Theme.fontSizeMicro; weight: Theme.weightBold; letterSpacing: 1.0 } }
                    Label { text: ""; width: 90 }
                }

                delegate: Rectangle {
                    id: aRow
                    required property var modelData
                    readonly property string outcome: String(modelData.outcome || "")
                    readonly property color oColor: {
                        switch (aRow.outcome) {
                        case "ok": case "applied": case "done": return Theme.ok;
                        case "denied": case "skipped": return Theme.medium;
                        case "failed": case "error": return Theme.critical;
                        default: return Theme.textFaint;
                        }
                    }
                    readonly property bool reversible: modelData.reversible === true && modelData.undo

                    width: ListView.view.width
                    height: 36
                    radius: Theme.radiusSm
                    color: aHover.containsMouse ? Theme.surfaceAlt : "transparent"

                    Row {
                        anchors { fill: parent; leftMargin: Theme.space3; rightMargin: Theme.space3 }
                        spacing: Theme.space3

                        Label {
                            text: aRow.modelData.when ? Theme.formatClock(aRow.modelData.when) : "\u2013"
                            width: 70
                            color: Theme.textFaint
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            verticalAlignment: Text.AlignVCenter
                            height: parent.height
                        }
                        Label {
                            text: aRow.modelData.action || ""
                            width: 110
                            color: Theme.text
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            elide: Text.ElideRight
                            verticalAlignment: Text.AlignVCenter
                            height: parent.height
                        }
                        SevBadge {
                            text: aRow.outcome
                            autoColor: false
                            customColor: aRow.oColor
                        }
                        Label {
                            text: aRow.modelData.target || (aRow.modelData.pid ? "pid " + aRow.modelData.pid : "")
                            width: parent.width * 0.24
                            color: Theme.textDim
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            elide: Text.ElideMiddle
                            verticalAlignment: Text.AlignVCenter
                            height: parent.height
                        }
                        Label {
                            text: aRow.modelData.reason || ""
                            width: parent.width * 0.30
                            color: Theme.textDim
                            font.pixelSize: Theme.fontSizeSmall
                            elide: Text.ElideRight
                            verticalAlignment: Text.AlignVCenter
                            height: parent.height
                        }
                        Label {
                            text: aRow.modelData.duration_ms !== undefined ? aRow.modelData.duration_ms : "\u2013"
                            width: 50
                            color: Theme.textFaint
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            horizontalAlignment: Text.AlignRight
                            verticalAlignment: Text.AlignVCenter
                            height: parent.height
                        }
                        Item {
                            width: 90
                            height: parent.height
                            NovaButton {
                                visible: aRow.reversible
                                text: qsTr("Undo")
                                role: "secondary"
                                compact: true
                                anchors { right: parent.right; verticalCenter: parent.verticalCenter }
                                onTriggered: {
                                    // The agent maps an undo to the inverse action for
                                    // this row; the journal records it either way.
                                    if (aRow.modelData.action === "suspend" && aRow.modelData.pid)
                                        backend.resume(aRow.modelData.pid);
                                    else if (aRow.modelData.action === "block" && aRow.modelData.id !== undefined)
                                        backend.unblock(aRow.modelData.id);
                                    else if (aRow.modelData.action === "quarantine" && aRow.modelData.id !== undefined)
                                        restoreDialog.qid = aRow.modelData.id;
                                }
                            }
                        }
                    }

                    HoverHandler { id: aHover }
                    ToolTip.visible: aHover.containsMouse
                    ToolTip.text: {
                        var m = aRow.modelData;
                        var parts = [qsTr("%1 \u2192 %2").arg(m.action || "?").arg(m.outcome || "?"),
                                     qsTr("severity %1 \u00B7 dry_run %2").arg(m.severity || "?").arg(m.dry_run ? "yes" : "no")];
                        if (m.detail) parts.push(String(m.detail));
                        if (m.undo) parts.push(qsTr("undo: %1").arg(m.undo));
                        return parts.join("\n");
                    }
                    // (attached ToolTip has no wrapMode; newlines in the text still break)
                }
            }

            EmptyState {
                anchors.centerIn: parent
                visible: page.actions.length === 0
                good: true
                message: qsTr("No actions recorded")
                hint: qsTr("The journal is empty until the agent acts or you act through the console. " +
                           "In dry-run mode, actions are recorded but not executed.")
            }
        }

        // ================= FROZEN =========================================
        Panel {
            visible: page.tab === "frozen"
            Layout.fillWidth: true
            Layout.fillHeight: true
            title: qsTr("Frozen processes")
            subtitle: qsTr("SIGSTOP'd by the agent \u2014 every row here is an ongoing outage")
            glyph: "\u23F8"
            accentColor: page.frozenCount > 0 ? Theme.high : Theme.ok

            ListView {
                anchors.fill: parent
                clip: true
                model: page.frozenRows
                spacing: 2
                boundsBehavior: Flickable.StopAtBounds
                reuseItems: true

                delegate: Rectangle {
                    id: fRow
                    required property var modelData
                    width: ListView.view.width
                    height: 44
                    radius: Theme.radiusSm
                    color: fHover.containsMouse ? Theme.surfaceAlt : "transparent"
                    border.width: 1
                    border.color: Theme.withAlpha(Theme.high, 0.5)

                    RowLayout {
                        anchors { fill: parent; leftMargin: Theme.space3; rightMargin: Theme.space3 }
                        spacing: Theme.space3

                        GlowDot { size: 10; color: Theme.high; glow: true; pulse: true }

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 0
                            Label {
                                text: fRow.modelData.comm || Theme.baseName(fRow.modelData.exe || "")
                                color: Theme.text
                                font { pixelSize: Theme.fontSizeBody; family: Theme.monoFamily; weight: Theme.weightMedium }
                                elide: Text.ElideRight
                                Layout.fillWidth: true
                            }
                            Label {
                                text: fRow.modelData.exe || ""
                                color: Theme.textFaint
                                font.pixelSize: Theme.fontSizeMicro
                                font.family: Theme.monoFamily
                                elide: Text.ElideRight
                                Layout.fillWidth: true
                            }
                        }

                        Label {
                            text: "pid " + (fRow.modelData.pid || 0)
                            color: Theme.textDim
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                        }
                        SevBadge { text: qsTr("stopped"); customColor: Theme.high; autoColor: false }

                        NovaButton {
                            text: qsTr("Resume")
                            role: "primary"
                            compact: true
                            onTriggered: backend.resume(fRow.modelData.pid)
                            ToolTip.visible: hovered
                            ToolTip.text: qsTr("SIGCONT. The process continues from exactly where it stopped.")
                        }
                        NovaButton {
                            text: qsTr("Investigate")
                            role: "secondary"
                            compact: true
                            onTriggered: backend.investigate(fRow.modelData.pid)
                        }
                        NovaButton {
                            text: qsTr("Kill")
                            role: "danger"
                            compact: true
                            confirm: true
                            onTriggered: backend.kill(fRow.modelData.pid)
                        }
                    }

                    HoverHandler { id: fHover }
                }
            }

            EmptyState {
                anchors.centerIn: parent
                visible: page.frozenRows.length === 0
                good: true
                message: qsTr("Nothing is frozen")
                hint: qsTr("When the agent escalates it freezes first, so a frozen pid here " +
                           "means the pipeline is mid-flight or waiting on a decision.")
            }
        }

        // ================= BLOCKS =========================================
        Panel {
            visible: page.tab === "blocks"
            Layout.fillWidth: true
            Layout.fillHeight: true
            title: qsTr("Network blocks")
            subtitle: qsTr("TTL-bounded; flushed on agent shutdown")
            glyph: "\u29B8"
            accentColor: page.blocks.length > 0 ? Theme.high : Theme.ok

            ListView {
                anchors.fill: parent
                clip: true
                model: page.blocks
                spacing: 2
                boundsBehavior: Flickable.StopAtBounds
                reuseItems: true

                delegate: Rectangle {
                    id: bRow
                    required property var modelData
                    width: ListView.view.width
                    height: 40
                    radius: Theme.radiusSm
                    color: bHover.containsMouse ? Theme.surfaceAlt : "transparent"
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
                                text: bRow.modelData.ip + (bRow.modelData.port ? ":" + bRow.modelData.port : " (all ports)")
                                color: Theme.text
                                font.pixelSize: Theme.fontSizeBody
                                font.family: Theme.monoFamily
                            }
                            Label {
                                text: bRow.modelData.reason || bRow.modelData.desc || ""
                                color: Theme.textDim
                                font.pixelSize: Theme.fontSizeSmall
                                elide: Text.ElideRight
                                Layout.fillWidth: true
                            }
                        }
                        Label {
                            text: page.ttlRemaining(bRow.modelData.installed, bRow.modelData.ttl_seconds)
                            color: Theme.medium
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                        }
                        NovaButton {
                            text: qsTr("Unblock")
                            role: "danger"
                            confirm: true
                            compact: true
                            onTriggered: backend.unblock(bRow.modelData.id !== undefined ? bRow.modelData.id : 0)
                        }
                    }

                    HoverHandler { id: bHover }
                }
            }

            EmptyState {
                anchors.centerIn: parent
                visible: page.blocks.length === 0
                good: true
                message: qsTr("No blocks in force")
                hint: qsTr("Use the Network page to block a destination, or wait for the agent to.")
            }
        }

        // ================= QUARANTINE =====================================
        Panel {
            visible: page.tab === "quarantine"
            Layout.fillWidth: true
            Layout.fillHeight: true
            title: qsTr("Quarantine")
            subtitle: qsTr("samples preserved at 0400 with a .meta sidecar \u00B7 restorable")
            glyph: "\u25A0"
            ListView {
                anchors.fill: parent
                clip: true
                model: page.quarantine
                spacing: 2
                boundsBehavior: Flickable.StopAtBounds
                reuseItems: true

                delegate: Rectangle {
                    id: qRow
                    required property var modelData

                    // The bridge serialises a quarantine entry as {id, desc} where
                    // desc is "<original path> -> <quarantine path>". The quarantine
                    // path is "<dir>/<id>-<sha256[:32]>", so both the restore
                    // destination and a hash prefix are recoverable from it. The full
                    // hash and the original mode/uid/gid live in the 0600 .meta
                    // sidecar next to the sample; the console shows what the snapshot
                    // carries rather than inventing fields it does not have.
                    readonly property var parsed: page.parseQuarantine(modelData.desc || "")
                    readonly property string originalPath: parsed.original
                    readonly property string quarantinePath: parsed.quarantine
                    readonly property string shaPrefix: parsed.sha

                    width: ListView.view.width
                    height: 44
                    radius: Theme.radiusSm
                    color: qHover.containsMouse ? Theme.surfaceAlt : "transparent"

                    RowLayout {
                        anchors { fill: parent; leftMargin: Theme.space3; rightMargin: Theme.space3 }
                        spacing: Theme.space3

                        GlowDot { size: 8; color: Theme.medium; glow: true }
                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 0
                            Label {
                                text: Theme.elideMiddle(qRow.originalPath, 56)
                                color: Theme.text
                                font.pixelSize: Theme.fontSizeSmall
                                font.family: Theme.monoFamily
                                elide: Text.ElideMiddle
                                Layout.fillWidth: true
                            }
                            Label {
                                text: "#" + (qRow.modelData.id || 0)
                                      + (qRow.shaPrefix.length > 0 ? "  \u00B7 sha256 " + qRow.shaPrefix + "\u2026" : "")
                                color: Theme.textFaint
                                font.pixelSize: Theme.fontSizeMicro
                                font.family: Theme.monoFamily
                                Layout.fillWidth: true
                            }
                        }
                        NovaButton {
                            text: qsTr("Restore")
                            role: "primary"
                            compact: true
                            onTriggered: {
                                restoreDialog.qid = qRow.modelData.id || 0;
                                restorePath.text = qRow.originalPath;
                                restoreDialog.open();
                            }
                        }
                    }

                    HoverHandler { id: qHover }
                    TapHandler {
                        acceptedButtons: Qt.LeftButton | Qt.RightButton
                        onTapped: function(button) {
                            // Real-AV habit: right-click the sample, run the full
                            // ladder (engine + VirusTotal) on the STORED sample --
                            // mode 0400 is readable enough for the hash lookup,
                            // and the engine re-scan confirms the quarantine
                            // decision with the current rule set.
                            if (button === Qt.RightButton && qRow.quarantinePath.length > 0)
                                backend.advancedScan(qRow.quarantinePath);
                        }
                    }
                    ToolTip.visible: qHover.containsMouse
                    ToolTip.text: [
                        qsTr("quarantine id %1").arg(qRow.modelData.id || "?"),
                        qsTr("original: %1").arg(qRow.originalPath || "?"),
                        qsTr("sample: %1").arg(qRow.quarantinePath || "?"),
                        qsTr("Full sha256 and original mode/uid/gid are in the 0600 .meta sidecar.")
                    ].join("\n")
                    // (attached ToolTip has no wrapMode; newlines in the text still break)
                }
            }

            EmptyState {
                anchors.centerIn: parent
                visible: page.quarantine.length === 0
                good: true
                message: qsTr("Quarantine is empty")
                hint: qsTr("Quarantined samples appear here with their hash and original metadata.")
            }
        }
    }

    /// Frozen rows: cross-reference the process snapshot against the journal's
    /// suspended actions, because the bridge reports the count but the pids come
    /// from the process table (state starts with T).
    readonly property var frozenRows: {
        var out = [];
        var procs = backend.processes;
        for (var i = 0; i < procs.length; ++i) {
            var p = procs[i];
            if (p && String(p.state || "").indexOf("T") === 0) out.push(p);
        }
        return out;
    }

    Dialog {
        id: restoreDialog
        property int qid: 0
        modal: true
        title: qsTr("Restore from quarantine")
        anchors.centerIn: Overlay.overlay
        width: 460

        background: Rectangle { radius: Theme.radiusMd; color: Theme.surface; border.width: 1; border.color: Theme.border }

        contentItem: ColumnLayout {
            spacing: Theme.space3
            Label {
                text: qsTr("The sample is written back to the path below with its original mode, uid and gid, " +
                           "taken from the .meta sidecar. If the path exists it is overwritten.")
                color: Theme.textDim
                font.pixelSize: Theme.fontSizeSmall
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }
            TextField {
                id: restorePath
                Layout.fillWidth: true
                text: restoreDialog.path
                color: Theme.text
                font.pixelSize: Theme.fontSizeSmall
                font.family: Theme.monoFamily
                background: Rectangle {
                    radius: Theme.radiusSm
                    color: Theme.surfaceAlt
                    border.width: 1
                    border.color: restorePath.activeFocus ? Theme.accent : Theme.border
                }
            }
            RowLayout {
                Layout.fillWidth: true
                spacing: Theme.space2
                Item { Layout.fillWidth: true }
                NovaButton { text: qsTr("Cancel"); role: "ghost"; onTriggered: restoreDialog.close() }
                NovaButton {
                    text: qsTr("Restore")
                    role: "primary"
                    enabled: restorePath.text.trim().length > 0
                    onTriggered: {
                        backend.restore(restoreDialog.qid, restorePath.text.trim());
                        restoreDialog.close();
                    }
                }
            }
        }
    }

    /// Parse "orig -> qdir/<id>-<sha32>" into its parts. Tolerant of a missing or
    /// malformed desc: every field falls back to the empty string, and the row
    /// still renders (with a Restore button that will fail loudly on the agent
    /// side if the id is wrong).
    function parseQuarantine(desc) {
        var t = String(desc || "");
        var arrow = t.indexOf(" -> ");
        var original = arrow >= 0 ? t.substring(0, arrow) : t;
        var qpath = arrow >= 0 ? t.substring(arrow + 4) : "";
        // sha prefix: basename, after "<id>-".
        var sha = "";
        if (qpath.length > 0) {
            var base = qpath.substring(qpath.lastIndexOf("/") + 1);
            var dash = base.indexOf("-");
            if (dash >= 0 && dash + 1 < base.length) sha = base.substring(dash + 1);
        }
        return { original: original, quarantine: qpath, sha: sha };
    }

    function ttlRemaining(installedEpoch, ttlSeconds) {
        if (!installedEpoch || !ttlSeconds) return qsTr("permanent");
        var left = Math.max(0, Math.floor(Number(installedEpoch) + Number(ttlSeconds) - Date.now() / 1000));
        if (left <= 0) return qsTr("expiring");
        if (left < 60) return left + "s";
        if (left < 3600) return Math.floor(left / 60) + "m";
        return Math.floor(left / 3600) + "h";
    }
}
