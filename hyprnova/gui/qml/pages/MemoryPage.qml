// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Memory Forensics page (Module 4c)
//
// What this page shows is exactly what the backend can honestly do: per-process
// inspection (maps + mem, W^X classification, signature matching) and an opt-in
// bounded dump. The limits banner is the backend's own words, not a paraphrase,
// so the page can never promise more than /proc allows.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import "../theme"
import "../components"

Item {
    id: page

    readonly property var status: backend.memStatus || {}
    readonly property var report: backend.memReport || {}

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

            // ================= LIMITS (honesty first) =====================
            Panel {
                Layout.fillWidth: true
                title: qsTr("What this module is")
                subtitle: qsTr("per-process inspection \u2014 and what it is not")
                glyph: "\u2695"
                accentColor: Theme.medium
                Label {
                    width: parent.width
                    text: String(page.status.limits || qsTr(
                        "Per-process inspection of /proc/<pid>/maps and /proc/<pid>/mem. " +
                        "NOT full system-memory forensics."))
                    color: Theme.textDim
                    font.pixelSize: Theme.fontSizeSmall
                    wrapMode: Text.Wrap
                }
                GridLayout {
                    Layout.fillWidth: true
                    columns: parent.width >= 800 ? 3 : 1
                    columnSpacing: Theme.space4
                    rowSpacing: Theme.space2

                    Repeater {
                        model: {
                            var t = page.status.tools || [];
                            var out = [];
                            for (var i = 0; i < t.length; ++i) out.push(t[i]);
                            return out;
                        }
                        delegate: RowLayout {
                            required property var modelData
                            Layout.fillWidth: true
                            spacing: Theme.space2
                            GlowDot {
                                size: 9
                                color: modelData.available ? Theme.good : Theme.textFaint
                            }
                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: 0
                                Label {
                                    text: modelData.name + (modelData.available ? "  \u2713" : "  \u2014")
                                    color: modelData.available ? Theme.text : Theme.textFaint
                                    font.pixelSize: Theme.fontSizeSmall
                                    font.family: Theme.monoFamily
                                }
                                Label {
                                    text: modelData.detail || ""
                                    color: Theme.textFaint
                                    font.pixelSize: Theme.fontSizeMicro
                                    wrapMode: Text.WrapAnywhere
                                    Layout.fillWidth: true
                                }
                            }
                        }
                    }
                }
            }

            // ================= INSPECT ====================================
            Panel {
                Layout.fillWidth: true
                title: qsTr("Inspect a process")
                subtitle: qsTr("maps + mem: W\u1D30X violations, strings, signature matches")
                glyph: "\u25CE"

                RowLayout {
                    width: parent.width
                    spacing: Theme.space3

                    Label { text: qsTr("PID"); color: Theme.textFaint; font.pixelSize: Theme.fontSizeSmall }
                    TextField {
                        id: pidField
                        Layout.preferredWidth: 140
                        placeholderText: "e.g. 1234"
                        font.family: Theme.monoFamily
                        validator: IntValidator { bottom: 2; top: 4194304 }
                    }
                    NovaButton {
                        text: qsTr("Inspect")
                        role: "primary"
                        enabled: pidField.text.length > 0
                        onTriggered: backend.inspectMemory(parseInt(pidField.text, 10))
                    }
                    Label {
                        // Handy: pick a suspicious actor straight from the Threats page.
                        text: qsTr("tip: right-click a process row \u2192 \u201CInspect memory\u201D")
                        color: Theme.textFaint
                        font.pixelSize: Theme.fontSizeMicro
                        Layout.fillWidth: true
                    }
                }
            }

            // ================= RESULTS ====================================
            Panel {
                Layout.fillWidth: true
                visible: Object.keys(page.report).length > 0
                title: qsTr("Inspection result")
                subtitle: "pid " + (page.report.pid || "?") + "  \u00B7  " + (page.report.exe || "")
                glyph: page.report.suspicious ? "\u26A0" : "\u2713"
                accentColor: page.report.suspicious ? Theme.critical : Theme.good

                ColumnLayout {
                    width: parent.width
                    spacing: Theme.space2

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space4
                        SevBadge {
                            text: page.report.suspicious ? "critical" : "clean"
                            solid: true
                        }
                        Label {
                            text: (page.report.regions_scanned || 0) + qsTr(" regions \u00B7 readable: ")
                                  + (page.report.readable ? "yes" : "NO")
                            color: Theme.textDim
                            font.pixelSize: Theme.fontSizeSmall
                        }
                    }

                    Label {
                        visible: String(page.report.limit_note || "").length > 0
                        text: qsTr("LIMIT: ") + (page.report.limit_note || "")
                        color: Theme.medium
                        font.pixelSize: Theme.fontSizeSmall
                        wrapMode: Text.Wrap
                        Layout.fillWidth: true
                    }

                    Repeater {
                        model: {
                            var f = page.report.findings || [];
                            var out = [];
                            for (var i = 0; i < f.length; ++i) out.push(String(f[i]));
                            return out;
                        }
                        delegate: Label {
                            required property string modelData
                            text: "\u2022 " + modelData
                            color: modelData.indexOf("VIOLATION") >= 0 ||
                                   modelData.indexOf("signature match") >= 0 ||
                                   modelData.indexOf("REUSE") >= 0
                                       ? Theme.critical : Theme.textDim
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            wrapMode: Text.WrapAnywhere
                            Layout.fillWidth: true
                        }
                    }

                    // Dump control: opt-in, explicit, warns about secrets.
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space3
                        Rectangle { Layout.fillWidth: true; height: 1; color: Theme.border }
                        NovaButton {
                            text: qsTr("Dump memory (0600, may contain secrets)")
                            role: "danger"
                            enabled: (page.report.pid || 0) > 1 && page.report.readable
                            onTriggered: dumpDialog.open()
                        }
                    }
                }
            }

            EmptyState {
                Layout.fillWidth: true
                visible: Object.keys(page.report).length === 0
                good: true
                message: qsTr("No inspection run yet")
                hint: qsTr("Pick a pid above, or right-click a suspicious process and choose \u201CInspect memory\u201D.")
            }
        }
    }

    Dialog {
        id: dumpDialog
        modal: true
        anchors.centerIn: Overlay.overlay
        width: Math.min(560, Window.window ? Window.window.width - 80 : 480)
        title: qsTr("Dump process memory?")
        background: Rectangle { color: Theme.surface; radius: Theme.radiusMd; border.color: Theme.border }

        ColumnLayout {
            width: parent.width
            spacing: Theme.space3
            Label {
                text: qsTr("pid %1 \u00B7 bounded to 512 MiB \u00B7 written 0600 under the agent's state dir.\n\n"
                           + "Memory can contain passwords, keys and session tokens. "
                           + "Treat the dump file as a secret; only share it with analysts who need it.")
                      .arg(page.report.pid || "?")
                color: Theme.textDim
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeSmall
                Layout.fillWidth: true
            }
            RowLayout {
                Layout.alignment: Qt.AlignRight
                spacing: Theme.space2
                NovaButton { text: qsTr("Cancel"); role: "ghost"; compact: true
                             onTriggered: dumpDialog.close() }
                NovaButton {
                    text: qsTr("Dump")
                    role: "danger"; compact: true
                    onTriggered: {
                        backend.dumpMemory(parseInt(pidField.text, 10) || (page.report.pid || 0));
                        dumpDialog.close();
                    }
                }
            }
        }
    }

    Connections {
        target: backend
        function onMemReportChanged() {
            // Keep the pid field in sync with the last inspection (right-click flow).
            var r = backend.memReport || {};
            if (r.pid) pidField.text = String(r.pid);
        }
    }
}
