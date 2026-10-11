// SPDX-License-Identifier: Apache-2.0
// HyprNova :: AI analyst page -- the Groq-powered forensic consultant.
//
// The contract is advises-only: the model never acts. It sees the posture
// summary and the latest bounded events (that is all ai_ask sends), and its
// answer lands here as TEXT for a human. Every containment action still goes
// through decisions + an operator answer. Without ai.enabled + api_key in the
// config the page says exactly that instead of pretending to think.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../theme"
import "../components"

Page {
    id: page

    property int pageIndex: 0

    background: Item {}

    readonly property var answer: backend.aiAnswer || {}
    // The toggle named ai_analyst is the consent switch; ai_ready/ai_note say
    // whether a usable key is actually configured (enabled != usable).
    readonly property var raw: (backend.settingsRaw && backend.settingsRaw.states)
                               ? backend.settingsRaw : {}
    readonly property var states: raw.states || {}
    readonly property bool aiEnabled: states["ai_analyst"] === true
    readonly property bool aiReady: raw["ai_ready"] === true
    readonly property string aiNote: String(raw["ai_note"] || "")
    readonly property bool hasAnswer: answer.ok === true && String(answer.answer || "").length > 0
    readonly property bool hasError: String(answer.error || "").length > 0

    ColumnLayout {
        anchors {
            fill: parent
            leftMargin: Theme.space5; rightMargin: Theme.space5
            topMargin: Theme.space4; bottomMargin: Theme.space4
        }
        spacing: Theme.space3

        // ---- header --------------------------------------------------------
        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.space3

            SectionTitle {
                Layout.fillWidth: true
                text: qsTr("AI forensic analyst")
                detail: qsTr("advises only — it can read posture + recent events, never act")
                color: Theme.accent
            }
            NovaButton {
                text: qsTr("Refresh consent state")
                role: "ghost"; compact: true
                onClicked: backend.refreshSettings()
            }
        }

        // ---- consent / honesty banner ---------------------------------------
        Panel {
            Layout.fillWidth: true
            accentColor: !page.aiEnabled ? Theme.medium
                       : (page.aiReady ? Theme.good : Theme.medium)
            glyph: "\u2726"
            title: !page.aiEnabled ? qsTr("Analyst disabled — consent is missing")
                 : (page.aiReady ? qsTr("Analyst enabled and ready (consultations leave the host)")
                                 : qsTr("Analyst enabled but NOT ready"))
            Label {
                width: parent.width
                wrapMode: Text.Wrap
                color: Theme.textDim
                font.pixelSize: Theme.fontSizeSmall
                text: page.aiEnabled
                    ? (page.aiReady
                       ? qsTr("Each question sends the posture summary and the most recent " +
                              "events to the configured Groq model. Answers are opinions, not " +
                              "verdicts: HyprNova's own detections and your answers decide actions.")
                       : qsTr("Consent is on, but the analyst reports: ") + page.aiNote +
                         qsTr("  — set ai.api_key (your Groq key) in agent.json."))
                  
                    : qsTr("The analyst needs ai.enabled = true and ai.api_key set " +
                           "(your Groq key, agent.json). Without consent nothing is sent " +
                           "anywhere — this page stays a manual notebook.")
        }
        }

        // ---- ask -------------------------------------------------------------
        Panel {
            Layout.fillWidth: true
            title: qsTr("Ask the analyst")
            glyph: "\u270E"

            ColumnLayout {
                width: parent.width
                spacing: Theme.space2

                ScrollView {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 84
                    TextArea {
                        id: question
                        placeholderText: qsTr("e.g. What should I check before answering the pending decision?")
                        wrapMode: TextArea.Wrap
                        color: Theme.text
                        font.pixelSize: Theme.fontSizeSmall
                        enabled: page.aiEnabled
                    }
                }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.space2

                    NovaButton {
                        text: qsTr("Send question")
                        role: "primary"
                        enabled: page.aiEnabled && question.text.trim().length > 0
                        onClicked: backend.askAi(question.text)
                    }

                    RowLayout {
                        spacing: Theme.space1
                        Label { text: qsTr("PID to review:"); color: Theme.textDim }
                        TextField {
                            id: reviewPid
                            placeholderText: "1234"
                            validator: IntValidator { bottom: 2; top: 4194304 }
                            Layout.preferredWidth: 110
                            enabled: page.aiEnabled
                        }
                        NovaButton {
                            text: qsTr("Review process")
                            role: "secondary"
                            enabled: page.aiEnabled && reviewPid.text.length > 0
                            onClicked: backend.reviewAi(parseInt(reviewPid.text, 10))
                        }
                    }
                }
            }
        }

        // ---- answer ----------------------------------------------------------
        Panel {
            Layout.fillWidth: true
            title: qsTr("Analyst reply")
            subtitle: page.hasAnswer
                      ? qsTr("model %1 · %2 ms").arg(String(answer.model || "?"))
                                           .arg(String(answer.elapsed_ms || "?"))
                      : qsTr("")
            accentColor: page.hasError ? Theme.high
                       : page.hasAnswer ? Theme.good : Theme.accent

            ColumnLayout {
                width: parent.width
                spacing: Theme.space2

                Label {
                    visible: !page.hasAnswer && !page.hasError
                    width: parent.width
                    wrapMode: Text.Wrap
                    color: Theme.textDim
                    text: qsTr("No consultation yet. Answers appear here verbatim — the analyst's " +
                               "text is never parsed into actions.")
                }

                Label {
                    visible: page.hasError
                    width: parent.width
                    wrapMode: Text.Wrap
                    color: Theme.high
                    text: String(answer.error || "")
                }

                Label {
                    visible: page.hasAnswer
                    width: parent.width
                    wrapMode: Text.Wrap
                    color: Theme.text
                    text: String(answer.answer || "")
                }
            }
        }

        Item { Layout.fillHeight: true }
    }
}
