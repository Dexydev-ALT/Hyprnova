// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Tools page -- the ecosystem coverage matrix (Module 8).
//
// One truthful screen: which of the ~80 registered ecosystem tools are on this
// host, how HyprNova uses each one (sensor / runner / exporter / inventory),
// and the always-on /proc security audit (seccomp posture of every process).
// Missing tools are facts, not errors -- the console says "not installed" and
// the role line says what installing it would buy.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../theme"
import "../components"

Page {
    id: page

    property int pageIndex: 0

    background: Item {}

    readonly property var toolbox: backend.toolbox || {}
    readonly property var summary: toolbox.summary || {}
    readonly property var procSec: toolbox.proc_security || {}
    readonly property var policy: toolbox.policy || {}
    readonly property var tools: toolbox.tools || []

    ColumnLayout {
        anchors {
            fill: parent
            leftMargin: Theme.space5; rightMargin: Theme.space5
            topMargin: Theme.space4; bottomMargin: Theme.space4
        }
        spacing: Theme.space3

        // ---- header ------------------------------------------------------------
        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.space3

            Label {
                text: qsTr("Toolbox")
                color: Theme.text
                font { pixelSize: Theme.fontSizeTitle; weight: Font.DemiBold }
                Layout.fillWidth: true
            }

            NovaButton {
                text: qsTr("Refresh")
                role: "ghost"
                compact: true
                glyph: "\u21BB"
                onTriggered: backend.refreshToolbox()
                ToolTip.visible: hovered
                ToolTip.text: qsTr("Re-probe every registered tool (~200 stat calls, always fresh).")
            }
        }

        // ---- combined scan launcher ------------------------------------------------
        // One command, many engines: the profile picks the toolset, the in-tree
        // engine always runs, missing external tools are reported as skipped.
        property string selectedProfile: "quick"
        Panel {
            Layout.fillWidth: true
            pad: Theme.space3

            RowLayout {
                anchors.fill: parent
                spacing: Theme.space3

                Label {
                    text: qsTr("Deep scan")
                    color: Theme.text
                    font { pixelSize: Theme.fontSizeBody; weight: Theme.weightBold }
                }

                Repeater {
                    model: [
                        { id: "quick",  label: qsTr("Quick") },
                        { id: "deep",   label: qsTr("Deep") },
                        { id: "kernel", label: qsTr("Kernel / rootkits") },
                        { id: "audit",  label: qsTr("Audit") }
                    ]

                    delegate: AbstractButton {
                        id: profChip
                        required property var modelData
                        readonly property bool on: page.selectedProfile === modelData.id
                        implicitWidth: chipLbl.implicitWidth + 20
                        implicitHeight: 26
                        background: Rectangle {
                            radius: 13
                            color: profChip.on ? Theme.withAlpha(Theme.accent, 0.18)
                                               : Theme.surfaceAlt
                            border.width: profChip.on ? 1 : 0
                            border.color: Theme.accentDim
                        }
                        contentItem: Label {
                            id: chipLbl
                            text: profChip.modelData.label
                            color: profChip.on ? Theme.accent : Theme.textDim
                            font { pixelSize: 10; weight: Theme.weightBold }
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                        }
                        onClicked: page.selectedProfile = profChip.modelData.id
                    }
                }

                Item { Layout.fillWidth: true }

                NovaButton {
                    text: qsTr("Run scan")
                    role: "primary"
                    compact: true
                    confirm: page.selectedProfile === "deep"   // deep can run long
                    onTriggered: {
                        backend.deepScan(page.selectedProfile);
                        toasts.push("info", qsTr("%1 scan started").arg(page.selectedProfile),
                                    qsTr("Results arrive as a toast; per-tool findings on this page."));
                    }
                }
            }
        }

        // ---- summary tiles -------------------------------------------------------
        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.space4

            Repeater {
                model: [
                    { label: qsTr("ECOSYSTEM"), value: (summary.installed || 0) + " / " + (summary.total || 0),
                      sub: qsTr("tools present"), ok: (summary.installed || 0) > 0 },
                    { label: qsTr("RUNNERS"), value: String(summary.runners_ready || 0),
                      sub: qsTr("ready to launch"), ok: (summary.runners_ready || 0) > 0 },
                    { label: qsTr("SECCOMP"), value: String(procSec.seccomp_filter || 0),
                      sub: qsTr("of %1 processes filtered").arg(procSec.processes || 0),
                      ok: (procSec.seccomp_none || 0) === 0 },
                    { label: qsTr("UPLOADS"), value: (policy.online_submission ? qsTr("on") : qsTr("off")),
                      sub: qsTr("sample privacy gate"), ok: !policy.online_submission }
                ]

                Panel {
                    required property var modelData
                    Layout.fillWidth: true
                    Layout.preferredHeight: 66
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
                            color: modelData.ok ? Theme.text : Theme.medium
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

        // ---- the matrix ----------------------------------------------------------
        ListView {
            id: list
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            model: page.tools
            spacing: 2
            boundsBehavior: Flickable.StopAtBounds
            ScrollBar.vertical: ScrollBar {}

            delegate: Rectangle {
                required property var modelData
                width: list.width
                height: 46
                radius: 8
                color: rowHover.hovered ? Theme.surfaceAlt : Theme.surface

                HoverHandler { id: rowHover }

                RowLayout {
                    anchors.fill: parent
                    anchors { leftMargin: Theme.space3; rightMargin: Theme.space3 }
                    spacing: Theme.space3

                    Rectangle {
                        width: 8; height: 8; radius: 4
                        Layout.alignment: Qt.AlignVCenter
                        color: modelData.installed
                               ? (modelData.integration === "built into HyprNova" ? Theme.accent : Theme.ok)
                               : "transparent"
                        border.width: modelData.installed ? 0 : 1
                        border.color: Theme.textFaint
                    }

                    ColumnLayout {
                        spacing: 0
                        Layout.fillWidth: true
                        Label {
                            text: modelData.label
                            color: modelData.installed ? Theme.text : Theme.textDim
                            font { pixelSize: Theme.fontSizeBody; weight: Theme.weightBold }
                        }
                        Label {
                            text: modelData.role
                            color: Theme.textFaint
                            font { pixelSize: 10 }
                            elide: Text.ElideRight
                            Layout.fillWidth: true
                            Layout.maximumHeight: 14
                        }
                    }

                    Rectangle {
                        Layout.alignment: Qt.AlignVCenter
                        implicitWidth: chip.implicitWidth + 16
                        implicitHeight: 20
                        radius: 10
                        color: Theme.withAlpha(Theme.accent, modelData.installed ? 0.12 : 0.05)
                        Label {
                            id: chip
                            anchors.centerIn: parent
                            text: modelData.integration
                            color: modelData.installed ? Theme.accent : Theme.textFaint
                            font { pixelSize: 9; weight: Theme.weightBold }
                        }
                    }

                    Label {
                        text: modelData.installed
                              ? (modelData.root_to_run && modelData.binary.length === 0
                                 ? qsTr("config present") : modelData.note)
                              : qsTr("not installed")
                        color: modelData.installed ? Theme.textFaint : Theme.textFaint
                        font { pixelSize: 10; family: Theme.monoFamily }
                        Layout.alignment: Qt.AlignVCenter
                        Layout.maximumWidth: 240
                        elide: Text.ElideMiddle
                    }
                }
            }

            section.property: "category"
            section.delegate: Item {
                required property string section
                width: list.width
                height: 30
                Label {
                    anchors { left: parent.left; bottom: parent.bottom; leftMargin: Theme.space1; bottomMargin: 4 }
                    text: section
                    color: Theme.textDim
                    font { pixelSize: Theme.fontSizeSmall; weight: Theme.weightBold }
                }
            }

            EmptyState {
                anchors.centerIn: parent
                visible: page.tools.length === 0
                good: false
                message: qsTr("The toolbox has not been probed yet")
                hint: qsTr("Press Refresh, or check that integrations.enabled is true in agent.json")
            }
        }

        // ---- footer notes ----------------------------------------------------------
        Panel {
            Layout.fillWidth: true
            pad: Theme.space3
            visible: page.procSec.unfiltered_root !== undefined &&
                     (page.procSec.unfiltered_root || []).length > 0

            ColumnLayout {
                anchors.fill: parent
                spacing: 4

                Label {
                    text: qsTr("Root processes WITHOUT seccomp filtering (kernel-exploit surface)")
                    color: Theme.medium
                    font { pixelSize: Theme.fontSizeSmall; weight: Theme.weightBold }
                }
                Label {
                    readonly property var samples: (page.procSec.unfiltered_root || [])
                    text: samples.slice(0, 6)
                          .map(function (p) { return "pid " + p.pid + " " + p.comm; })
                          .join("   \u00B7   ")
                    color: Theme.textDim
                    font { pixelSize: 10; family: Theme.monoFamily }
                    elide: Text.ElideRight
                    Layout.fillWidth: true
                }
            }
        }

        Label {
            Layout.fillWidth: true
            text: qsTr("Run a tool from the terminal:  hyprnova-cli tool-run rkhunter   \u00B7   "
                       + "online verdicts:  hyprnova-cli vt-lookup <sha256>  (needs an API key in agent.json)")
            color: Theme.textFaint
            font { pixelSize: 10; family: Theme.monoFamily }
            wrapMode: Text.WordWrap
        }
    }
}
