// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Threats
//
// The analyst's page. Three regions, in the order an analyst reads them during a
// live incident:
//
//   1. PENDING DECISIONS   — processes the agent has frozen and is holding. Until
//                           these are answered, services are down. Always on top.
//   2. RISK ACTORS         — the ranked list of who is accumulating score. The
//                           score, its band, the trigger set, and whether the
//                           actor is still alive (an exited pid that hit Critical
//                           is an IOC, not an emergency).
//   3. EVENT FEED          — the raw stream, newest first, with severity filter
//                           chips. This is the page an operator leaves on a second
//                           monitor.
//
// Everything clickable leads to an action, and every destructive action goes through
// NovaButton's two-step confirm. The feed itself is a ListView with reuseItems:
// at 4 Hz and a 2000-event history the delegate count is the real cost, and
// EventRow owns no timers, so recycling is safe here.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import "../theme"
import "../components"

Item {
    id: page

    /// Severity filter. Empty string == show everything. Chips are exclusive: the
    /// operator is answering "show me the criticals", not "also the lows".
    property string severityFilter: ""

    /// Text filter fed by the shell's top-bar search (Ctrl+F, Enter lands here).
    property string textFilter: ""
    Component.onCompleted: {
        if (typeof Window.window !== "undefined" && Window.window.searchQuery !== undefined)
            textFilter = Window.window.searchQuery;
    }

    readonly property var filteredEvents: {
        var out = [];
        var ev = backend.events;
        var needle = page.textFilter.toLowerCase();
        for (var i = 0; i < ev.length && out.length < 400; ++i) {
            if (page.severityFilter.length !== 0
                && String(ev[i].severity || "").toLowerCase() !== page.severityFilter) {
                continue;
            }
            if (needle.length > 0
                && String(ev[i].message || "").toLowerCase().indexOf(needle) < 0
                && String(ev[i].sensor || "").toLowerCase().indexOf(needle) < 0
                && String(ev[i].kind || "").toLowerCase().indexOf(needle) < 0) {
                continue;
            }
            out.push(ev[i]);
        }
        return out;
    }

    readonly property var pendingDecisions: backend.decisions
    readonly property var summary: backend.riskSummary

    // ---- layout ----
    RowLayout {
        anchors.fill: parent
        anchors.margins: Theme.space5
        spacing: Theme.space4

        // ---- left column: decisions + actors ----
        ColumnLayout {
            Layout.preferredWidth: parent.width * 0.42
            Layout.fillHeight: true
            spacing: Theme.space4

            // ============ PENDING DECISIONS =============================
            Panel {
                Layout.fillWidth: true
                Layout.fillHeight: page.pendingDecisions.length > 0
                Layout.preferredHeight: page.pendingDecisions.length > 0 ? -1 : 120
                title: qsTr("Awaiting your decision")
                subtitle: page.pendingDecisions.length > 0
                          ? qsTr("%1 process(es) frozen \u2014 answering releases them")
                                .arg(page.pendingDecisions.length)
                          : qsTr("nothing is waiting")
                glyph: "\u26A0"
                accentColor: page.pendingDecisions.length > 0 ? Theme.critical : Theme.ok

                ListView {
                    id: decisionsList
                    anchors.fill: parent
                    clip: true
                    model: page.pendingDecisions
                    spacing: Theme.space2
                    boundsBehavior: Flickable.StopAtBounds

                    delegate: Rectangle {
                        id: dCard
                        required property var modelData
                        readonly property var report: modelData.report || {}
                        readonly property var factors: modelData.factors || []
                        readonly property color sevColor: Theme.severityColor(report.severity || "high")
                        readonly property bool frozen: report.suspended === true && report.resumed !== true

                        width: ListView.view.width
                        height: dCol.height + Theme.space3 * 2
                        radius: Theme.radiusMd
                        color: Theme.withAlpha(dCard.sevColor, 0.07)
                        border.width: 1
                        border.color: Theme.withAlpha(dCard.sevColor, 0.5)

                        // Pulsing spine while the process is frozen: this card
                        // represents an ongoing outage.
                        Rectangle {
                            anchors { left: parent.left; top: parent.top; bottom: parent.bottom }
                            width: 3
                            radius: Theme.radiusMd
                            color: dCard.sevColor
                        }

                        ColumnLayout {
                            id: dCol
                            anchors {
                                left: parent.left; right: parent.right; top: parent.top
                                leftMargin: Theme.space4; rightMargin: Theme.space3; topMargin: Theme.space3
                            }
                            spacing: Theme.space2

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: Theme.space2

                                GlowDot {
                                    size: 12
                                    color: dCard.sevColor
                                    glow: true
                                    pulse: dCard.frozen
                                }
                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 0
                                    Label {
                                        text: Theme.baseName(dCard.report.exe || "") || qsTr("unknown")
                                        color: Theme.text
                                        font { pixelSize: Theme.fontSizeBody; family: Theme.monoFamily; weight: Theme.weightBold }
                                        elide: Text.ElideRight
                                        Layout.fillWidth: true
                                    }
                                    Label {
                                        text: qsTr("pid %1 \u00B7 risk %2 \u00B7 frozen for %3")
                                              .arg(dCard.report.pid || 0)
                                              .arg(Math.round(dCard.report.risk || 0))
                                              .arg(dCard.frozen ? qsTr("yes") : qsTr("no"))
                                        color: Theme.textDim
                                        font.pixelSize: Theme.fontSizeSmall
                                        font.family: Theme.monoFamily
                                        elide: Text.ElideRight
                                        Layout.fillWidth: true
                                    }
                                }
                                SevBadge { text: report.severity || "high"; solid: true }
                            }

                            // Top two factors, so the operator sees WHY without
                            // opening the dialog. Full evidence is one click away.
                            Repeater {
                                model: dCard.factors.slice(0, 2)
                                delegate: RowLayout {
                                    required property var modelData
                                    Layout.fillWidth: true
                                    spacing: Theme.space2
                                    Label {
                                        text: (modelData.points >= 0 ? "+" : "") + (modelData.points || 0)
                                        color: Theme.riskColor(modelData.points || 0)
                                        Layout.preferredWidth: 40
                                        horizontalAlignment: Text.AlignRight
                                        font { pixelSize: Theme.fontSizeSmall; family: Theme.monoFamily; weight: Theme.weightBold }
                                    }
                                    Label {
                                        text: modelData.trigger || ""
                                        color: Theme.textDim
                                        font.pixelSize: Theme.fontSizeSmall
                                        elide: Text.ElideRight
                                        Layout.fillWidth: true
                                    }
                                }
                            }

                            Label {
                                text: qsTr("recommendation: %1").arg(dCard.modelData.recommendation || "review")
                                color: Theme.textFaint
                                font.pixelSize: Theme.fontSizeSmall
                                visible: (dCard.modelData.recommendation || "").length > 0
                                Layout.fillWidth: true
                                elide: Text.ElideRight
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: Theme.space2

                                NovaButton {
                                    text: qsTr("Review")
                                    role: "primary"
                                    compact: true
                                    Layout.fillWidth: true
                                    onTriggered: {
                                        // Open the full dialog with all evidence.
                                        Window.window.threatDialogOpen(modelData);
                                    }
                                }
                                NovaButton {
                                    text: qsTr("Resume")
                                    role: "secondary"
                                    compact: true
                                    onTriggered: backend.answer(modelData.id, "allow")
                                    ToolTip.visible: hovered
                                    ToolTip.text: qsTr("Unfreeze and let it run. Reversible.")
                                }
                                NovaButton {
                                    text: qsTr("Kill")
                                    role: "danger"
                                    compact: true
                                    confirm: true
                                    onTriggered: backend.answer(modelData.id, "kill")
                                    ToolTip.visible: hovered
                                    ToolTip.text: qsTr("SIGKILL after preserving the executable as evidence.")
                                }
                            }
                        }
                    }
                }

                EmptyState {
                    anchors.centerIn: parent
                    visible: page.pendingDecisions.length === 0
                    good: true
                    message: qsTr("No decisions pending")
                    hint: qsTr("When the agent freezes a process it appears here immediately.")
                }
            }

            // ============ RISK ACTORS ===================================
            Panel {
                Layout.fillWidth: true
                Layout.fillHeight: true
                title: qsTr("Risk actors")
                subtitle: qsTr("%1 tracked \u00B7 top %2").arg(backend.riskActors.length)
                                            .arg(Math.round(page.summary.top_score || 0))
                glyph: "\u26A0"
                accentColor: Theme.riskColor(page.summary.top_score || 0)
                headerRight: Label {
                    text: qsTr("alert %1 \u00B7 critical %2 \u00B7 auto %3")
                          .arg(page.summary.thresholds_alert || 500)
                          .arg(page.summary.thresholds_critical || 750)
                          .arg(page.summary.thresholds_auto || 850)
                    color: Theme.textFaint
                    font.pixelSize: Theme.fontSizeMicro
                    font.family: Theme.monoFamily
                }

                ListView {
                    id: actors
                    anchors.fill: parent
                    clip: true
                    model: backend.riskActors
                    spacing: 3
                    boundsBehavior: Flickable.StopAtBounds
                    reuseItems: true

                    delegate: Rectangle {
                        id: aRow
                        required property var modelData
                        readonly property int score: modelData.score || 0
                        readonly property bool alive: modelData.alive !== false
                        readonly property bool frozen: modelData.suspended === true
                        readonly property bool prompted: modelData.prompted === true

                        width: ListView.view.width
                        height: 58
                        radius: Theme.radiusSm
                        color: aHover.containsMouse ? Theme.surfaceAlt : "transparent"
                        border.width: aRow.frozen ? 1 : 0
                        border.color: Theme.withAlpha(Theme.high, 0.55)

                        RowLayout {
                            anchors {
                                fill: parent
                                leftMargin: Theme.space3; rightMargin: Theme.space3
                            }
                            spacing: Theme.space3

                            GlowDot {
                                size: 10
                                color: Theme.riskColor(aRow.score)
                                glow: aRow.score >= (page.summary.thresholds_alert || 500)
                                pulse: aRow.frozen
                            }

                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: 2

                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: Theme.space2
                                    Label {
                                        text: aRow.modelData.comm || Theme.baseName(aRow.modelData.exe || "")
                                        color: aRow.alive ? Theme.text : Theme.textFaint
                                        font { pixelSize: Theme.fontSizeBody; family: Theme.monoFamily; weight: Theme.weightMedium }
                                        elide: Text.ElideRight
                                        Layout.maximumWidth: 200
                                    }
                                    SevBadge {
                                        text: aRow.modelData.severity || "info"
                                        visible: aRow.modelData.severity
                                    }
                                    Label {
                                        visible: !aRow.alive
                                        text: qsTr("exited")
                                        color: Theme.textFaint
                                        font.pixelSize: Theme.fontSizeMicro
                                    }
                                    Label {
                                        visible: aRow.prompted
                                        text: qsTr("prompted")
                                        color: Theme.medium
                                        font.pixelSize: Theme.fontSizeMicro
                                    }
                                    Item { Layout.fillWidth: true }
                                    Label {
                                        text: aRow.score
                                        color: Theme.riskColor(aRow.score)
                                        font { pixelSize: Theme.fontSizeTitle; family: Theme.monoFamily; weight: Theme.weightBold }
                                    }
                                }

                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: Theme.space2
                                    Label {
                                        text: "pid " + (aRow.modelData.pid || 0) + " \u00B7 uid " + (aRow.modelData.uid || 0)
                                        color: Theme.textFaint
                                        font.pixelSize: Theme.fontSizeMicro
                                        font.family: Theme.monoFamily
                                    }
                                    Label {
                                        text: qsTr("%1 events \u00B7 %2 triggers")
                                              .arg(aRow.modelData.events || 0)
                                              .arg(aRow.modelData.distinct_triggers || 0)
                                        color: Theme.textFaint
                                        font.pixelSize: Theme.fontSizeMicro
                                        font.family: Theme.monoFamily
                                    }
                                    Item { Layout.fillWidth: true }
                                    Label {
                                        // Last update as a relative age. Absolute
                                        // timestamps are in the tooltip; on a live page
                                        // "3s ago" is what the eye wants.
                                        text: page.relativeAge(aRow.modelData.last_update)
                                        color: Theme.textFaint
                                        font.pixelSize: Theme.fontSizeMicro
                                        font.family: Theme.monoFamily
                                    }
                                }

                                RiskBar {
                                    risk: aRow.score
                                    showValue: false
                                    compact: true
                                    Layout.fillWidth: true
                                    Layout.preferredHeight: 4
                                    thresholds: [ (page.summary.thresholds_alert || 500) / 1000,
                                                  (page.summary.thresholds_critical || 750) / 1000,
                                                  (page.summary.thresholds_auto || 850) / 1000 ]
                                }
                            }
                        }

                        HoverHandler { id: aHover }
                        TapHandler {
                            acceptedButtons: Qt.LeftButton | Qt.RightButton
                            onTapped: function(button) {
                                // Right-click: run the Advanced-scan ladder on the
                                // actor's executable, like a real AV's file menu.
                                if (button === Qt.RightButton) {
                                    var exe = String(aRow.modelData.exe || "");
                                    if (exe.length > 0) backend.advancedScan(exe);
                                    else backend.investigate(aRow.modelData.pid);
                                    return;
                                }
                                backend.investigate(aRow.modelData.pid);
                            }
                            onDoubleTapped: Window.window.goTo(2)
                        }
                        ToolTip.visible: aHover.containsMouse
                        ToolTip.text: {
                            var m = aRow.modelData;
                            var parts = [m.exe || m.comm || "",
                                         m.cmdline || "",
                                         qsTr("score %1 (peak %2) \u00B7 severity %3")
                                             .arg(Math.round(m.score || 0))
                                             .arg(Math.round(m.peak || 0))
                                             .arg(m.severity || "?"),
                                         qsTr("lineage: %1").arg((m.lineage || []).join(" \u2192 ")),
                                         qsTr("first seen %1 \u00B7 last update %2")
                                             .arg(Theme.formatDate(m.first_seen || 0))
                                             .arg(Theme.formatDate(m.last_update || 0)),
                                         qsTr("triggers: %1").arg((m.triggers || []).join(", "))];
                            if (m.container) parts.push(qsTr("container: %1").arg(m.container));
                            return parts.filter(function(s) { return s.length > 0; }).join("\n");
                        }
                        // (attached ToolTip has no wrapMode; newlines in the text still break)
                    }
                }

                EmptyState {
                    anchors.centerIn: parent
                    visible: backend.riskActors.length === 0
                    good: true
                    message: qsTr("No actor has crossed a threshold")
                    hint: qsTr("Scores accumulate per process and decay when it stops misbehaving.")
                }
            }
        }

        // ---- right column: event feed ----
        Panel {
            Layout.fillWidth: true
            Layout.fillHeight: true
            title: qsTr("Event feed")
            subtitle: page.severityFilter.length > 0
                      ? qsTr("filtered: %1 \u2014 %2 of %3").arg(page.severityFilter)
                          .arg(page.filteredEvents.length).arg(backend.events.length)
                      : qsTr("%1 events in history").arg(backend.events.length)
            glyph: "\u25B6"
            headerRight: RowLayout {
                spacing: Theme.space1

                Repeater {
                    model: ["", "critical", "high", "medium", "low", "info"]
                    delegate: NovaButton {
                        required property string modelData
                        required property int index
                        text: modelData.length === 0 ? qsTr("ALL") : modelData.toUpperCase()
                        role: page.severityFilter === modelData ? "primary" : "ghost"
                        compact: true
                        Layout.preferredWidth: modelData.length === 0 ? 48 : 72
                        onTriggered: page.severityFilter = modelData
                    }
                }
            }

            ListView {
                id: feed
                anchors.fill: parent
                clip: true
                model: page.filteredEvents
                spacing: 1
                boundsBehavior: Flickable.StopAtBounds
                // 400 rows of live telemetry: the delegate must be cheap. EventRow
                // is two Rectangles, a few Labels and no timers, and reuseItems
                // keeps the pool at the visible height + cacheBuffer.
                reuseItems: true
                cacheBuffer: 600
                // Follow the newest event by default. Pinned to the top because the
                // model is newest-first, so "position 0" is "the newest".
                property bool follow: true
                onContentYChanged: follow = contentY < 4
                onModelChanged: if (follow) positionViewAtBeginning()

                header: Item { width: 1; height: 2 }

                delegate: EventRow {
                    required property var modelData
                    event: modelData
                    width: ListView.view.width
                    onInvestigateRequested: function(pid) { backend.investigate(pid); }
                    onClicked: function(ev) {
                        // Selecting a row in the feed does not navigate; it opens the
                        // investigation dialog for the actor, which is what an analyst
                        // means by "look at this".
                        if (ev && ev.actor && ev.actor.pid > 0) backend.investigate(ev.actor.pid);
                    }
                }

                // Auto-scroll to the top when a new event lands AND the operator has
                // not scrolled down to read. If they have scrolled, jumping would be
                // actively hostile.
                Connections {
                    target: backend
                    function onEventsChanged() {
                        if (feed.follow) feed.positionViewAtBeginning();
                    }
                }
            }

            EmptyState {
                anchors.centerIn: parent
                visible: page.filteredEvents.length === 0
                good: page.severityFilter.length === 0
                message: page.severityFilter.length > 0
                         ? qsTr("No %1 events").arg(page.severityFilter)
                         : qsTr("No events recorded")
                hint: page.severityFilter.length > 0
                      ? qsTr("Clear the filter to see everything.")
                      : qsTr("Sensors are up; nothing has crossed a threshold.")
            }
        }
    }

    /// Seconds -> "3s" / "2m" / "1h". Used for "last update" on a live page where
    /// absolute timestamps are noise.
    function relativeAge(epochSeconds) {
        if (!epochSeconds) return qsTr("never");
        var d = Math.max(0, Math.floor(Date.now() / 1000) - Number(epochSeconds));
        if (d < 60) return d + "s";
        if (d < 3600) return Math.floor(d / 60) + "m";
        if (d < 86400) return Math.floor(d / 3600) + "h";
        return Math.floor(d / 86400) + "d";
    }
}
