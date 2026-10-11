// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Incident timeline -- one chronological thread of everything the
// agent saw, filtered by severity, with the containment decisions inline.
//
// Investigate-don't-convict: rows show what was OBSERVED. Nothing on this page
// changes system state; actions stay on the pages that own them (decision
// answers on Remediation, inspection on Memory).

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../theme"
import "../components"

Page {
    id: page

    property int pageIndex: 0

    background: Item {}

    readonly property var evs: {
        var src = backend.events || [];
        var out = [];
        for (var i = 0; i < src.length; ++i) out.push(src[i]);
        return out;
    }
    readonly property var decs: {
        var src = backend.decisions || [];
        var out = [];
        for (var i = 0; i < src.length; ++i) out.push(src[i]);
        return out;
    }
    property string sevFilter: "all"
    readonly property var filtered: {
        var out = [];
        for (var i = 0; i < page.evs.length; ++i) {
            var e = page.evs[i];
            if (page.sevFilter === "high" &&
                !(String(e.severity) === "high" || String(e.severity) === "critical")) continue;
            out.push(e);
        }
        return out;
    }
    readonly property int highCount: {
        var n = 0;
        for (var i = 0; i < page.evs.length; ++i) {
            var s = String(page.evs[i].severity);
            if (s === "high" || s === "critical") ++n;
        }
        return n;
    }

    function fmtTime(ts) {
        var v = Number(ts);
        if (!isFinite(v) || v <= 0) return "";
        return new Date(v * 1000).toLocaleTimeString(Qt.locale(), "HH:mm:ss");
    }

    Component.onCompleted: { backend.refreshEvents(400); backend.refreshDecisions(); }

    ColumnLayout {
        anchors {
            fill: parent
            leftMargin: Theme.space5; rightMargin: Theme.space5
            topMargin: Theme.space4; bottomMargin: Theme.space4
        }
        spacing: Theme.space3

        // ---- header + filters --------------------------------------------------
        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.space2
            SectionTitle {
                Layout.fillWidth: true
                text: qsTr("Incident timeline")
                detail: qsTr("%1 events (%2 high/critical) · %3 decisions")
                            .arg(page.evs.length).arg(page.highCount).arg(page.decs.length)
            }
            RowLayout {
                spacing: Theme.space1
                NovaButton {
                    text: qsTr("All")
                    role: page.sevFilter === "all" ? "primary" : "ghost"
                    compact: true
                    onClicked: page.sevFilter = "all"
                }
                NovaButton {
                    text: qsTr("High+")
                    role: page.sevFilter === "high" ? "primary" : "ghost"
                    compact: true
                    onClicked: page.sevFilter = "high"
                }
                NovaButton {
                    text: qsTr("Refresh")
                    role: "ghost"; compact: true
                    onClicked: { backend.refreshEvents(400); backend.refreshDecisions(); }
                }
            }
        }

        // ---- the thread ----------------------------------------------------------
        Panel {
            Layout.fillWidth: true
            Layout.fillHeight: true
            title: qsTr("Events")
            subtitle: page.sevFilter === "high"
                      ? qsTr("showing high & critical only") : qsTr("newest first")

            ListView {
                id: feed
                width: parent.width
                height: parent.height
                clip: true
                model: page.filtered
                spacing: Theme.space1

                ScrollBar.vertical: ScrollBar {}

                EmptyState {
                    anchors.centerIn: parent
                    visible: feed.count === 0
                    message: qsTr("Nothing here yet")
                    hint: page.sevFilter === "high"
                          ? qsTr("No high/critical events in the current buffer — lower the filter.")
                          : qsTr("The agent has not published events in this session yet.")
                }

                delegate: RowLayout {
                    required property var modelData
                    width: feed.width
                    spacing: Theme.space2

                    Label {
                        Layout.preferredWidth: 64
                        color: Theme.textFaint
                        font.pixelSize: Theme.fontSizeSmall
                        font.family: "monospace"
                        text: page.fmtTime(modelData.ts)
                    }
                    SevBadge {
                        text: String(modelData.severity || "info")
                    }
                    Label {
                        Layout.preferredWidth: 96
                        color: Theme.textFaint
                        font.pixelSize: Theme.fontSizeSmall
                        elide: Text.ElideRight
                        text: String(modelData.sensor || "")
                    }
                    Label {
                        Layout.fillWidth: true
                        wrapMode: Text.Wrap
                        color: Theme.text
                        font.pixelSize: Theme.fontSizeSmall
                        text: String(modelData.message || "")
                    }
                }
            }
        }

        // ---- decisions ------------------------------------------------------------
        Panel {
            Layout.fillWidth: true
            title: qsTr("Containment decisions")
            subtitle: qsTr("observations + the verdict each needs from you")

            ColumnLayout {
                width: parent.width
                spacing: Theme.space1

                EmptyState {
                    visible: page.decs.length === 0
                    message: qsTr("No pending decisions")
                    hint: qsTr("When the engine escalates an actor, the decision and its " +
                               "evidence appear here and on Remediation.")
                    good: true
                }

                Repeater {
                    model: page.decs
                    delegate: RowLayout {
                        required property var modelData
                        width: parent.width
                        spacing: Theme.space2

                        SevBadge {
                            text: String(modelData.severity ||
                                         (Number(modelData.risk) >= 850 ? "critical" : "high"))
                        }
                        Label {
                            Layout.preferredWidth: 150
                            color: Theme.text
                            font.pixelSize: Theme.fontSizeSmall
                            elide: Text.ElideRight
                            text: String(modelData.comm || modelData.actor?.comm || "?") +
                                  (modelData.pid ? " (" + String(modelData.pid) + ")" : "")
                        }
                        Label {
                            Layout.fillWidth: true
                            wrapMode: Text.Wrap
                            color: Theme.textDim
                            font.pixelSize: Theme.fontSizeSmall
                            text: qsTr("risk %1 — %2")
                                      .arg(String(modelData.risk ?? "?"))
                                      .arg(String(modelData.reason || modelData.summary || ""))
                        }
                    }
                }
            }
        }
    }
}
