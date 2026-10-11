// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Home page -- the triage screen.
//
// Modelled on the reference design's home: a big hero with the protection
// verdict and a glowing shield, real (never promotional) recommendation cards,
// and a Quick Scan launch panel. Under it, a compact live strip so this screen
// is still an EDR console and not a screensaver.
//
// Everything shown is DERIVED FROM THE AGENT: the headline is the posture score,
// the bullets are sensor/baseline facts, the cards are generated from actual
// findings. No fake marketing rows.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../theme"
import "../components"

Page {
    id: page

    property int pageIndex: 0

    // The verdict. Thresholds mirror the agent's own posture bands.
    readonly property string verdict: {
        var s = backend.postureScore;
        if (!backend.connected) return qsTr("Waiting for the agent\u2026");
        if (s >= 85) return qsTr("We've got you covered");
        if (s >= 60) return qsTr("You're protected \u2014 with a few gaps");
        if (s >= 35) return qsTr("Your protection needs attention");
        return qsTr("Action required");
    }
    readonly property string mood: {
        var s = backend.postureScore;
        if (!backend.connected) return "warn";
        if (s >= 85) return "ok";
        if (s >= 35) return "warn";
        return "bad";
    }

    background: Item {}

    // Recommendations are computed when the overview refreshes: they are facts
    // (dry run on, sensors degraded, drift found), not a static list.
    readonly property var recommendations: {
        var recs = [];
        if (!backend.connected) return recs;
        if (backend.pendingDecisions > 0)
            recs.push({ kicker: "THREATS", danger: true, idx: 1, action: qsTr("Review"),
                        title: backend.pendingDecisions === 1
                               ? qsTr("A threat is waiting on your decision")
                               : qsTr("%1 threats are waiting on your decision").arg(backend.pendingDecisions) });
        if (backend.sensorsDegraded > 0)
            recs.push({ kicker: "COVERAGE", danger: false, idx: 2, action: qsTr("Details"),
                        title: qsTr("%1 sensors are degraded \u2014 coverage is partial").arg(backend.sensorsDegraded) });
        var drift = 0;
        try {
            var kb = backend.hardening ? backend.hardening.kernel_hardening : null;
            drift = (kb && kb.drift) ? kb.drift : 0;
        } catch (e) { drift = 0; }
        if (drift > 0)
            recs.push({ kicker: "HARDENING", danger: false, idx: 5, action: qsTr("Turn on"),
                        title: qsTr("%1 kernel hardening settings have drifted").arg(drift) });
        if (backend.dryRun)
            recs.push({ kicker: "MODE", danger: true, idx: 9, action: qsTr("Settings"),
                        title: qsTr("The agent is in dry run \u2014 it observes but never acts") });
        else if (!backend.autoRespond)
            recs.push({ kicker: "POLICY", danger: false, idx: 9, action: qsTr("Settings"),
                        title: qsTr("Auto-respond is off \u2014 critical findings will wait for you") });
        return recs;
    }

    ColumnLayout {
        anchors {
            fill: parent
            leftMargin: Theme.space6; rightMargin: Theme.space6
            topMargin: Theme.space5; bottomMargin: Theme.space5
        }
        spacing: Theme.space5

        // ---- hero ------------------------------------------------------------
        Item {
            Layout.fillWidth: true
            Layout.preferredHeight: 240

            RowLayout {
                anchors.fill: parent
                spacing: Theme.space5

                HeroShield {
                    mood: page.mood
                    Layout.preferredWidth: 280
                    Layout.preferredHeight: 230
                    Layout.alignment: Qt.AlignVCenter
                }

                ColumnLayout {
                    spacing: Theme.space3
                    Layout.fillWidth: true
                    Layout.alignment: Qt.AlignVCenter

                    Label {
                        text: page.verdict
                        color: Theme.text
                        font {
                            pixelSize: 30
                            family: Theme.fontFamily
                            weight: Font.DemiBold
                        }
                    }

                    // The three facts that explain the verdict.
                    ColumnLayout {
                        spacing: 6

                        Repeater {
                            model: [
                                {
                                    dot: backend.sensorsDegraded > 0 ? Theme.medium : Theme.accent,
                                    text: backend.sensorsRunning > 0
                                          ? (backend.sensorsDegraded > 0
                                             ? qsTr("Automatic threat detection \u2014 %1 sensors up, %2 degraded")
                                                 .arg(backend.sensorsRunning).arg(backend.sensorsDegraded)
                                             : qsTr("Automatic threat detection \u2014 all %1 sensors up")
                                                 .arg(backend.sensorsRunning))
                                          : qsTr("Automatic threat detection \u2014 sensors offline")
                                },
                                {
                                    dot: backend.learning ? Theme.medium : Theme.accent,
                                    text: backend.learning
                                          ? qsTr("Learning baseline \u2014 %1% complete")
                                              .arg(Math.round(backend.learningProgress * 100))
                                          : qsTr("Behavioural baseline established")
                                },
                                {
                                    dot: backend.eventsDropped > 0 ? Theme.high : Theme.accent,
                                    text: backend.eventsDropped > 0
                                          ? qsTr("Event bus under pressure \u2014 %1 dropped")
                                              .arg(window.formatCount(backend.eventsDropped))
                                          : qsTr("Event pipeline healthy \u2014 %1 events handled")
                                              .arg(window.formatCount(backend.eventsPublished))
                                }
                            ]

                            Row {
                                spacing: 8
                                Rectangle {
                                    width: 6; height: 6; radius: 3
                                    anchors.verticalCenter: parent.verticalCenter
                                    color: modelData.dot
                                }
                                Label {
                                    text: modelData.text
                                    color: Theme.textDim
                                    font { pixelSize: Theme.fontSizeBody; family: Theme.fontFamily }
                                    anchors.verticalCenter: parent.verticalCenter
                                }
                            }
                        }
                    }

                    NovaButton {
                        text: qsTr("Details")
                        role: "primary"
                        Layout.topMargin: Theme.space2
                        onTriggered: window.goTo(5)
                        ToolTip.visible: hovered
                        ToolTip.text: qsTr("Open the Hardening audit that drives the posture score.")
                    }
                }
            }
        }

        // ---- recommendations ---------------------------------------------------
        ColumnLayout {
            Layout.fillWidth: true
            spacing: Theme.space3

            Label {
                text: qsTr("Recommendations")
                color: Theme.text
                font { pixelSize: Theme.fontSizeTitle; weight: Font.DemiBold }
            }

            Row {
                Layout.fillWidth: true
                spacing: Theme.space4
                visible: page.recommendations.length > 0

                Repeater {
                    // Two-up, like the reference. More findings than two live in
                    // Hardening / Threats; the hero Details button leads there.
                    model: page.recommendations.slice(0, 2)

                    RecommendationCard {
                        required property var modelData
                        Layout.preferredWidth: Math.min(400, (page.width - Theme.space6 * 2 - Theme.space4) / 2)
                        kicker: modelData.kicker
                        danger: modelData.danger
                        title: modelData.title
                        actionLabel: modelData.action
                        onActionClicked: window.goTo(modelData.idx)
                    }
                }
            }

            // All-clear card: the reference shows offers when there is nothing to
            // say; we show the one honest "nothing to act on" row instead.
            Panel {
                Layout.fillWidth: true
                visible: page.recommendations.length === 0
                pad: Theme.space4
                RowLayout {
                    anchors.fill: parent
                    spacing: Theme.space3
                    NavIcon {
                        name: "shield"
                        color: Theme.accent
                        width: 18; height: 18
                    }
                    Label {
                        text: qsTr("No recommendations right now \u2014 sensors, policy and hardening all look clean.")
                        color: Theme.textDim
                        font.pixelSize: Theme.fontSizeBody
                        Layout.fillWidth: true
                    }
                }
            }
        }

        // ---- quick scan ----------------------------------------------------------
        Panel {
            id: quickPanel
            Layout.fillWidth: true
            Layout.preferredHeight: 86
            pad: 0

            property bool menuOpen: false

            MouseArea {
                id: quickHot
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: backend.fullSweep()
                enabled: false   // the big button is the real trigger; area is for hover feedback only
            }

            RowLayout {
                anchors.fill: parent
                anchors { leftMargin: Theme.space5; rightMargin: Theme.space4 }
                spacing: Theme.space4

                Rectangle {
                    width: 44; height: 44; radius: 22
                    color: Theme.withAlpha(Theme.accent, 0.14)
                    NavIcon {
                        name: "scan"
                        color: Theme.accent
                        width: 22; height: 22
                        anchors.centerIn: parent
                    }
                }

                ColumnLayout {
                    spacing: 2
                    Layout.fillWidth: true
                    Label {
                        text: backend.scanCounters.sweep_running
                              ? qsTr("Sweep running \u2014 %1%").arg(Math.round(backend.scanCounters.sweep_progress * 100))
                              : qsTr("Quick Scan")
                        color: Theme.text
                        font { pixelSize: Theme.fontSizeTitle; weight: Font.DemiBold }
                    }
                    Label {
                        text: backend.scanCounters.sweep_running
                              ? qsTr("scanning: %1").arg(backend.scanCounters.sweep_current || "\u2026")
                              : qsTr("Scan the live filesystem for known malware signatures")
                        color: Theme.textFaint
                        font.pixelSize: Theme.fontSizeSmall
                        elide: Text.ElideMiddle
                        Layout.maximumWidth: 420
                    }
                }

                NovaButton {
                    text: qsTr("Scan now")
                    role: "primary"
                    confirm: true          // a full sweep is minutes of I/O
                    busy: backend.scanCounters.sweep_running
                    onTriggered: {
                        backend.fullSweep();
                        toasts.push("info", qsTr("Full sweep started"),
                                    qsTr("Progress is live on the Scanning page."));
                    }
                }

                // Chevron menu: scan a specific path instead of the full sweep.
                AbstractButton {
                    id: chevron
                    width: 30; height: 30
                    Layout.alignment: Qt.AlignVCenter
                    background: Rectangle {
                        radius: 15
                        color: chevron.hovered ? Theme.surfaceAlt : "transparent"
                    }
                    contentItem: Label {
                        text: "\u203A"
                        color: Theme.textDim
                        font { pixelSize: 22; weight: Font.DemiBold }
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                        rotation: pathMenu.opened ? 90 : 0
                        Behavior on rotation { NumberAnimation { duration: Theme.animFast } }
                    }
                    onClicked: pathMenu.opened ? pathMenu.close() : pathMenu.open()
                }
            }

            Popup {
                id: pathMenu
                y: parent.height + 4
                x: parent.width - width - Theme.space4
                width: 320
                padding: Theme.space3
                background: Rectangle {
                    radius: 10
                    color: Theme.raised
                    border.width: 1
                    border.color: Theme.border
                }

                ColumnLayout {
                    anchors.fill: parent
                    spacing: Theme.space2

                    Label {
                        text: qsTr("Scan a specific path")
                        color: Theme.textDim
                        font { pixelSize: Theme.fontSizeSmall; weight: Theme.weightBold }
                    }
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space2
                        Rectangle {
                            Layout.fillWidth: true
                            height: 32
                            radius: 6
                            color: Theme.searchBg
                            border.width: pathInput.activeFocus ? 1 : 0
                            border.color: Theme.accentDim
                            TextInput {
                                id: pathInput
                                anchors { fill: parent; leftMargin: 10; rightMargin: 10 }
                                verticalAlignment: TextInput.AlignVCenter
                                color: Theme.text
                                font { pixelSize: Theme.fontSizeBody; family: Theme.monoFamily }
                                text: "/home"
                                selectByMouse: true
                            }
                        }
                        NovaButton {
                            text: qsTr("Scan")
                            role: "secondary"
                            compact: true
                            onTriggered: {
                                var p = pathInput.text.trim();
                                if (p.length === 0) return;
                                backend.scanPath(p);
                                pathMenu.close();
                                toasts.push("info", qsTr("Scan queued: %1").arg(p),
                                            qsTr("The Scanning page shows the result."));
                                window.goTo(4);
                            }
                        }
                    }
                }
            }
        }

        Item { Layout.fillHeight: true }

        // ---- live strip ----------------------------------------------------------
        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.space4

            Repeater {
                model: [
                    { label: qsTr("EVENTS"),    value: window.formatCount(backend.eventsPublished), sub: qsTr("published") },
                    { label: qsTr("DROPPED"),   value: window.formatCount(backend.eventsDropped),   sub: backend.eventsDropped > 0 ? qsTr("backpressure!") : qsTr("none") },
                    { label: qsTr("TOP RISK"),  value: String(Math.round(backend.riskSummary.top_score || 0)), sub: qsTr("of 1000") },
                    { label: qsTr("DECISIONS"), value: String(backend.pendingDecisions),            sub: qsTr("waiting on you") },
                    { label: qsTr("UPTIME"),    value: Theme.formatUptime(backend.uptime),          sub: backend.postureLabel }
                ]

                Panel {
                    required property var modelData
                    Layout.fillWidth: true
                    Layout.preferredHeight: 64
                    pad: Theme.space3

                    ColumnLayout {
                        anchors.fill: parent
                        spacing: 1

                        Label {
                            text: modelData.label
                            color: Theme.textFaint
                            font { pixelSize: 9; weight: Theme.weightBold; letterSpacing: 1.2 }
                        }
                        Label {
                            text: modelData.value
                            color: modelData.label === "DROPPED" && backend.eventsDropped > 0
                                   ? Theme.high : Theme.text
                            font {
                                pixelSize: Theme.fontSizeLarge
                                family: Theme.monoFamily
                                weight: Theme.weightBold
                            }
                        }
                        Label {
                            text: modelData.sub
                            color: Theme.textFaint
                            font.pixelSize: 9
                            elide: Text.ElideRight
                            Layout.fillWidth: true
                        }
                    }
                }
            }
        }
    }
}
