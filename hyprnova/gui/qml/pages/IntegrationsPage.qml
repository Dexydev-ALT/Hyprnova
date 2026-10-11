// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Integrations page -- drive the registered ecosystem tools and
// the VirusTotal hash lookup from one surface.
//
// Truthful by construction: what you see is the tool's parsed output (summary,
// findings, error). An absent tool is reported as "not installed" by the
// daemon; a missing VT key fails with the daemon's own message. Nothing here
// fabricates results. ToolsPage shows the coverage matrix; this page RUNS one.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../theme"
import "../components"

Page {
    id: page

    property int pageIndex: 0

    background: Item {}

    readonly property var result: backend.toolResult || {}
    readonly property bool hasResult: Object.keys(result).length > 0
    readonly property var findingsList: {
        var f = result.findings || [];
        var out = [];
        for (var i = 0; i < f.length; ++i) out.push(String(f[i]));
        return out;
    }

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
                text: qsTr("Integrations")
                detail: qsTr("run a registered tool or a VirusTotal hash lookup — output is shown verbatim")
            }
            Label {
                color: Theme.textFaint
                font.pixelSize: Theme.fontSizeSmall
                text: qsTr("keys & toggles live in Settings")
            }
        }

        // ---- tool runner -----------------------------------------------------
        Panel {
            Layout.fillWidth: true
            title: qsTr("Run a tool")
            glyph: "\u25B6"

            ColumnLayout {
                width: parent.width
                spacing: Theme.space2

                Label {
                    width: parent.width
                    wrapMode: Text.Wrap
                    color: Theme.textDim
                    font.pixelSize: Theme.fontSizeSmall
                    text: qsTr("Tool ids as registered: kvrt, crowdsec, pkg-verify, sshd-config, " +
                               "rkhunter, chkrootkit, lynis, clamav … (see Tools for what is installed). " +
                               "A run blocks until the tool finishes; built-in audits return instantly.")
                }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.space2

                    Label { text: qsTr("tool:"); color: Theme.textDim }
                    TextField {
                        id: toolName
                        placeholderText: "sshd-config"
                        Layout.preferredWidth: 220
                    }
                    Label { text: qsTr("args:"); color: Theme.textDim }
                    TextField {
                        id: toolArgs
                        placeholderText: qsTr("optional, space separated")
                        Layout.preferredWidth: 260
                    }
                    NovaButton {
                        text: qsTr("Run")
                        role: "primary"
                        enabled: toolName.text.trim().length > 0
                        onClicked: {
                            var a = [];
                            var parts = toolArgs.text.split(" ");
                            for (var i = 0; i < parts.length; ++i)
                                if (parts[i].trim().length > 0) a.push(parts[i].trim());
                            backend.runTool(toolName.text.trim(), a);
                        }
                    }
                }
            }
        }

        // ---- VirusTotal -------------------------------------------------------
        Panel {
            Layout.fillWidth: true
            title: qsTr("VirusTotal hash lookup")
            glyph: "\u2693"

            ColumnLayout {
                width: parent.width
                spacing: Theme.space2

                Label {
                    width: parent.width
                    wrapMode: Text.Wrap
                    color: Theme.textDim
                    font.pixelSize: Theme.fontSizeSmall
                    text: qsTr("Look up a SHA-256 (no file upload — hash query only). Needs " +
                               "integrations.virustotal_api_key in agent.json; without it the " +
                               "daemon refuses with the exact reason.")
                }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.space2
                    TextField {
                        id: vtHash
                        Layout.fillWidth: true
                        placeholderText: qsTr("64-hex sha256")
                        font.family: "monospace"
                    }
                    NovaButton {
                        text: qsTr("Look up")
                        role: "secondary"
                        enabled: /^[0-9a-fA-F]{64}$/.test(vtHash.text.trim())
                        onClicked: backend.vtLookup(vtHash.text.trim())
                    }
                }
            }
        }

        // ---- result -------------------------------------------------------------
        Panel {
            Layout.fillWidth: true
            title: qsTr("Last result")
            subtitle: hasResult ? String(result.tool || result.cmd || "") : qsTr("")
            accentColor: hasResult
                         ? (String(result.error || "").length > 0 ? Theme.high
                            : (result.ok === true ? Theme.good : Theme.medium))
                         : Theme.accent

            ColumnLayout {
                width: parent.width
                spacing: Theme.space2

                Label {
                    visible: !page.hasResult
                    width: parent.width
                    color: Theme.textDim
                    wrapMode: Text.Wrap
                    text: qsTr("Nothing run yet.")
                }

                Label {
                    visible: page.hasResult && String(result.summary || "").length > 0
                    width: parent.width
                    wrapMode: Text.Wrap
                    color: Theme.text
                    font.pixelSize: Theme.fontSizeSmall
                    text: String(result.summary || "")
                }

                Label {
                    visible: page.hasResult && String(result.error || "").length > 0
                    width: parent.width
                    wrapMode: Text.Wrap
                    color: Theme.high
                    text: String(result.error || "")
                }

                Repeater {
                    visible: page.findingsList.length > 0
                    model: page.findingsList
                    delegate: Label {
                        required property string modelData
                        width: parent.width
                        wrapMode: Text.Wrap
                        color: Theme.text
                        font.pixelSize: Theme.fontSizeSmall
                        font.family: "monospace"
                        text: "• " + modelData
                    }
                }
            }
        }

        Item { Layout.fillHeight: true }
    }
}
