// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Processes
//
// The live process tree with a detail drawer. Two things make this page different
// from a `ps` output sorted by risk:
//
//   1. IT IS A TREE, and the flags are on the rows. Deleted-exe, writable-path,
//      traced and shell-under-a-daemon are the four things an analyst hunts for;
//      burying them in a column means they are never found. They get chips.
//   2. THE DETAIL DRAWER IS PREDICTIVE, NOT RETROSPECTIVE. Selecting a row shows
//      the actions available for THAT pid, and the tree already knows which pids
//      have risk history — because backend.lineageOf() walks the cached snapshot,
//      the drawer costs no round trip.
//
// The tree itself is ProcessTree (flattened model, expand/collapse, filter).
// Filtering also expands ancestors, so "filter for curl" always shows the curl you
// are looking for rather than hiding it under a collapsed parent.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import "../theme"
import "../components"

Item {
    id: page

    property string filter: ""
    property var selected: null

    readonly property var caps: backend.processes.length > 0
                              ? {} : {}
    // The bridge's snapshot_processes returns {processes, count, root, capabilities}.
    // backend.processes is the flat list; the capability block is only present on
    // the first snapshot, so it is read from the raw reply when available. Here we
    // just need the list.
    readonly property var procs: backend.processes

    readonly property var lineage: page.selected ? backend.lineageOf(page.selected.pid) : []
    readonly property var children: page.selected ? backend.childrenOf(page.selected.pid) : []
    readonly property bool frozen: page.selected
                                  ? String(page.selected.state || "").indexOf("T") === 0 : false

    RowLayout {
        anchors.fill: parent
        anchors.margins: Theme.space5
        spacing: Theme.space4

        // ---- tree ----
        Panel {
            Layout.fillWidth: true
            Layout.fillHeight: true
            title: qsTr("Process tree")
            subtitle: qsTr("%1 processes in snapshot").arg(page.procs.length)
            glyph: "\u2261"
            headerRight: RowLayout {
                spacing: Theme.space2

                // Filter. Debounced by a short timer so typing "nginx" does not
                // rebuild the flattened model five times.
                TextField {
                    id: filterBox
                    Layout.preferredWidth: 220
                    placeholderText: qsTr("filter by name, path or cmdline\u2026")
                    color: Theme.text
                    placeholderTextColor: Theme.textFaint
                    font.pixelSize: Theme.fontSizeSmall
                    font.family: Theme.fontFamily
                    background: Rectangle {
                        radius: Theme.radiusSm
                        color: Theme.surfaceAlt
                        border.width: 1
                        border.color: filterBox.activeFocus ? Theme.accent : Theme.border
                    }
                    onTextChanged: filterDebounce.restart()
                }

                NovaButton {
                    text: qsTr("Expand")
                    role: "ghost"
                    compact: true
                    onTriggered: tree.expandAll()
                }
                NovaButton {
                    text: qsTr("Collapse")
                    role: "ghost"
                    compact: true
                    onTriggered: tree.collapseAll()
                }
                NovaButton {
                    text: qsTr("Refresh")
                    role: "ghost"
                    compact: true
                    glyph: "\u21BB"
                    onTriggered: backend.refreshProcesses(400)
                }
            }

            ProcessTree {
                id: tree
                anchors.fill: parent
                processes: page.procs
                filter: page.filter
                showKernelThreads: false
                rowH: 36

                onRowClicked: function(proc) { page.selected = proc; }
                onRowDoubleClicked: function(proc) {
                    page.selected = proc;
                    if (proc && proc.pid > 0) backend.investigate(proc.pid);
                }
                onInvestigateRequested: function(pid) { backend.investigate(pid); }
            }
        }

        // ---- detail drawer ----
        Panel {
            id: drawer
            Layout.preferredWidth: 380
            Layout.fillHeight: true
            visible: page.selected !== null
            title: page.selected ? page.selected.comm || qsTr("process") : ""
            subtitle: page.selected
                      ? qsTr("pid %1 \u00B7 ppid %2 \u00B7 uid %3")
                            .arg(page.selected.pid).arg(page.selected.ppid).arg(page.selected.uid)
                      : ""
            glyph: page.frozen ? "\u23F8" : "\u25A6"
            accentColor: page.frozen ? Theme.high : Theme.accent

            Flickable {
                anchors.fill: parent
                contentWidth: width
                contentHeight: detailCol.height + Theme.space4
                clip: true
                boundsBehavior: Flickable.StopAtBounds
                ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                ColumnLayout {
                    id: detailCol
                    width: parent.width
                    spacing: Theme.space4

                    // ---- headline ----
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space2

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: Theme.space2
                            GlowDot {
                                size: 12
                                color: page.frozen ? Theme.high
                                     : String(page.selected.state) === "Z" ? Theme.down : Theme.ok
                                glow: true
                                pulse: page.frozen
                            }
                            Label {
                                text: page.frozen ? qsTr("FROZEN by the agent") : String(page.selected.state || "?")
                                color: page.frozen ? Theme.high : Theme.textDim
                                font { pixelSize: Theme.fontSizeBody; family: Theme.fontFamily; weight: Theme.weightBold }
                                Layout.fillWidth: true
                                elide: Text.ElideRight
                            }
                        }

                        Label {
                            text: page.selected.exe || ""
                            color: Theme.text
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            wrapMode: Text.WrapAnywhere
                            Layout.fillWidth: true
                        }
                        Label {
                            text: page.selected.cmdline || ""
                            color: Theme.textDim
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            wrapMode: Text.WrapAnywhere
                            Layout.fillWidth: true
                            visible: (page.selected.cmdline || "").length > 0
                        }
                    }

                    Rectangle { Layout.fillWidth: true; height: 1; color: Theme.border }

                    // ---- attributes ----
                    GridLayout {
                        Layout.fillWidth: true
                        columns: 2
                        columnSpacing: Theme.space3
                        rowSpacing: Theme.space1

                        Repeater {
                            model: [
                                { k: qsTr("pid"),      v: page.selected.pid },
                                { k: qsTr("ppid"),     v: page.selected.ppid },
                                { k: qsTr("tgid"),     v: page.selected.tgid },
                                { k: qsTr("uid"),      v: page.selected.uid },
                                { k: qsTr("euid"),     v: page.selected.euid },
                                { k: qsTr("threads"),  v: page.selected.threads },
                                { k: qsTr("vsize"),    v: Theme.formatBytes(page.selected.vsize || 0) },
                                { k: qsTr("rss"),      v: Theme.formatBytes(page.selected.rss_bytes || 0) },
                                { k: qsTr("age"),      v: Theme.formatUptime(page.selected.age_seconds || 0) },
                                { k: qsTr("cwd"),      v: page.selected.cwd || "" },
                                { k: qsTr("cgroup"),   v: Theme.elideMiddle(page.selected.cgroup || "", 40) },
                                { k: qsTr("container"),v: page.selected.container || "" }
                            ]
                            delegate: ColumnLayout {
                                required property var modelData
                                Layout.fillWidth: true
                                spacing: 0
                                Label {
                                    text: modelData.k
                                    color: Theme.textFaint
                                    font { pixelSize: Theme.fontSizeMicro; family: Theme.fontFamily; weight: Theme.weightBold; letterSpacing: 0.8 }
                                }
                                Label {
                                    text: String(modelData.v === undefined || modelData.v === null ? "" : modelData.v)
                                    color: Theme.textDim
                                    font.pixelSize: Theme.fontSizeSmall
                                    font.family: Theme.monoFamily
                                    wrapMode: Text.WrapAnywhere
                                    Layout.fillWidth: true
                                }
                            }
                        }
                    }

                    Rectangle { Layout.fillWidth: true; height: 1; color: Theme.border }

                    // ---- lineage ----
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space2
                        visible: page.lineage.length > 1

                        SectionTitle { text: qsTr("Lineage") }
                        Repeater {
                            model: page.lineage
                            delegate: RowLayout {
                                required property var modelData
                                required property int index
                                Layout.fillWidth: true
                                spacing: Theme.space2
                                Label {
                                    text: index === page.lineage.length - 1 ? "\u25B6" : "\u2514"
                                    color: index === page.lineage.length - 1 ? Theme.accent : Theme.textFaint
                                    font.pixelSize: Theme.fontSizeSmall
                                }
                                Label {
                                    text: modelData.comm + " (" + modelData.pid + ")"
                                    color: index === page.lineage.length - 1 ? Theme.text : Theme.textDim
                                    font.pixelSize: Theme.fontSizeSmall
                                    font.family: Theme.monoFamily
                                    elide: Text.ElideRight
                                    Layout.fillWidth: true
                                }
                            }
                        }
                    }

                    Rectangle {
                        Layout.fillWidth: true; height: 1; color: Theme.border
                        visible: page.lineage.length > 1
                    }

                    // ---- children ----
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space2
                        visible: page.children.length > 0

                        SectionTitle {
                            text: qsTr("Children")
                            detail: String(page.children.length)
                        }
                        Repeater {
                            model: page.children.slice(0, 12)
                            delegate: RowLayout {
                                required property var modelData
                                Layout.fillWidth: true
                                spacing: Theme.space2
                                GlowDot {
                                    size: 6
                                    color: String(modelData.state || "").indexOf("T") === 0 ? Theme.high : Theme.textFaint
                                }
                                Label {
                                    text: modelData.comm + " (" + modelData.pid + ")"
                                    color: Theme.textDim
                                    font.pixelSize: Theme.fontSizeSmall
                                    font.family: Theme.monoFamily
                                    elide: Text.ElideRight
                                    Layout.fillWidth: true
                                }
                            }
                        }
                    }

                    Rectangle {
                        Layout.fillWidth: true; height: 1; color: Theme.border
                        visible: page.children.length > 0
                    }

                    // ---- actions ----
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space2

                        SectionTitle { text: qsTr("Actions") }

                        NovaButton {
                            text: qsTr("Investigate \u2014 full escalation pipeline")
                            role: "primary"
                            Layout.fillWidth: true
                            onTriggered: backend.investigate(page.selected.pid)
                            ToolTip.visible: hovered
                            ToolTip.text: qsTr("Freeze, dump /proc/<pid>/maps, YARA the memory strings, " +
                                               "batch-scan the lineage, then prompt you with the evidence.")
                        }

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: Theme.space2

                            NovaButton {
                                text: page.frozen ? qsTr("Resume") : qsTr("Freeze")
                                role: page.frozen ? "primary" : "secondary"
                                Layout.fillWidth: true
                                onTriggered: page.frozen
                                             ? backend.resume(page.selected.pid)
                                             : backend.suspend(page.selected.pid)
                            }
                            NovaButton {
                                text: qsTr("Isolate")
                                role: "secondary"
                                Layout.fillWidth: true
                                onTriggered: backend.isolate(page.selected.pid)
                                ToolTip.visible: hovered
                                ToolTip.text: qsTr("cgroup: pids.max=16, cpu.max throttled, memory.max=256M, frozen.")
                            }
                        }

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: Theme.space2

                            NovaButton {
                                text: qsTr("Scan exe")
                                role: "secondary"
                                Layout.fillWidth: true
                                enabled: (page.selected.exe || "").length > 0
                                onTriggered: backend.scanPath(page.selected.exe)
                            }
                            NovaButton {
                                text: qsTr("Quarantine")
                                role: "danger"
                                confirm: true
                                Layout.fillWidth: true
                                enabled: (page.selected.exe || "").length > 0
                                onTriggered: backend.quarantine(page.selected.exe)
                            }
                        }

                        NovaButton {
                            text: qsTr("Kill process")
                            role: "danger"
                            confirm: true
                            Layout.fillWidth: true
                            onTriggered: backend.kill(page.selected.pid)
                        }
                    }

                    Item { Layout.fillHeight: true }
                }
            }
        }

        // Shown when nothing is selected: a hint rather than an empty panel, so
        // the drawer's absence does not look like a bug.
        EmptyState {
            visible: page.selected === null
            anchors.centerIn: parent
            message: qsTr("Select a process")
            hint: qsTr("Click a row for attributes, lineage and actions. Double-click to investigate immediately.")
        }
    }

    Timer {
        id: filterDebounce
        interval: 180
        onTriggered: page.filter = filterBox.text
    }
}
