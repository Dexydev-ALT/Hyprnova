// SPDX-License-Identifier: Apache-2.0
// HyprNova :: live process tree
//
// Flattened-model approach. QML's TreeView needs a QAbstractItemModel, which would
// mean either a C++ proxy model or rebuilding a nested JS structure on every
// refresh. Instead: the flat process list from the agent is walked once into a
// depth-ordered array of rows, and a plain ListView renders it with a left indent
// per depth and an expand/collapse chevron.
//
// Why that is the right trade: at 4 Hz with ~600 processes, one O(n) flatten pass
// is cheaper than a model reset, the ListView recycles delegates so only the
// visible ~30 rows cost anything, and expand/collapse is a Set lookup rather than
// a structural change.
//
// The rows that matter are flagged: a deleted executable, a run-from-world-
// writable-path, an active ptrace, a container escape candidate. Those are the
// four things an analyst actually hunts for in a process list, so they get a
// coloured chip instead of being buried in a column.

import QtQuick
import QtQuick.Controls
import "../theme"

Item {
    id: root

    /// Flat list from backend.processes: [{pid, ppid, comm, exe, state, uid, ...}].
    property var processes: []
    /// Optional filter substring matched against comm/exe/cmdline.
    property string filter: ""
    /// Show kernel threads. Off by default: they are noise on every Linux host.
    property bool showKernelThreads: false
    /// Row height; kept tight so a 600-process host is scrollable in one screen.
    property int rowH: Theme.rowHeight

    /// pid -> expanded. A plain object is enough; reassigning it forces the model
    /// to rebuild, which is what we want on toggle.
    property var expanded: ({})
    /// pid -> true for rows matching the filter. Computed with the model so a
    /// filter hit also reveals its ancestors (otherwise the match is unreachable).
    property var matches: ({})

    signal rowClicked(var proc)
    signal rowDoubleClicked(var proc)
    signal investigateRequested(int pid)

    /// The flattened, visible rows.
    property var rows: []

    function toggle(pid) {
        var e = Object.assign({}, root.expanded);
        e[pid] = !e[pid];
        root.expanded = e;
    }

    function expandAll() {
        var e = {};
        for (var i = 0; i < root.processes.length; ++i) e[root.processes[i].pid] = true;
        root.expanded = e;
    }

    function collapseAll() { root.expanded = {}; }

    /// Rebuild the flat row list. Depth-first from every root (ppid not present in
    /// the snapshot, which includes pid 1 and orphans re-parented to it).
    function rebuild() {
        var procs = root.processes || [];
        var byPid = {};
        var childrenOf = {};
        var i, p;

        var filterLower = root.filter.toLowerCase();
        var matching = {};
        var anyFilter = filterLower.length > 0;

        for (i = 0; i < procs.length; ++i) {
            p = procs[i];
            if (p === undefined || p === null) continue;
            byPid[p.pid] = p;
            if (!childrenOf[p.ppid]) childrenOf[p.ppid] = [];
            childrenOf[p.ppid].push(p);

            if (anyFilter) {
                var hay = ((p.comm || "") + " " + (p.exe || "") + " " + (p.cmdline || "")).toLowerCase();
                if (hay.indexOf(filterLower) >= 0) matching[p.pid] = true;
            }
        }

        // A filter hit must reveal its whole ancestry, or the operator filters for
        // "curl" and sees nothing because curl's parent row is collapsed.
        var visibleByFilter = {};
        if (anyFilter) {
            for (var pidStr in matching) {
                var cur = Number(pidStr);
                var guard = 0;
                while (cur && byPid[cur] && guard++ < 32) {
                    visibleByFilter[cur] = true;
                    var parent = byPid[cur].ppid;
                    if (parent === cur) break;
                    cur = parent;
                }
            }
        }
        root.matches = matching;

        // Sort siblings by start time so the tree reads chronologically: the thing
        // that just spawned is at the bottom of its parent's block, which is where
        // the eye already goes.
        for (var key in childrenOf) {
            childrenOf[key].sort(function(a, b) { return (a.start_time || 0) - (b.start_time || 0); });
        }

        var out = [];
        var visited = {};

        function walk(proc, depth) {
            if (!proc || visited[proc.pid]) return;   // a pid cycle cannot hang us
            visited[proc.pid] = true;

            var kernelThread = (proc.exe === undefined || proc.exe === null || proc.exe === "")
                               && proc.uid === 0;
            if (kernelThread && !root.showKernelThreads && !matching[proc.pid]) return;
            if (anyFilter && !visibleByFilter[proc.pid]) return;

            out.push({ proc: proc, depth: depth,
                       hasChildren: (childrenOf[proc.pid] || []).length > 0,
                       isOpen: !!root.expanded[proc.pid],
                       matched: !!matching[proc.pid] });

            if (root.expanded[proc.pid] || anyFilter) {
                var kids = childrenOf[proc.pid] || [];
                for (var k = 0; k < kids.length; ++k) walk(kids[k], depth + 1);
            }
        }

        // Roots: ppid missing from the snapshot, or self-parented, or pid 1.
        var roots = [];
        for (i = 0; i < procs.length; ++i) {
            p = procs[i];
            if (p === undefined || p === null) continue;
            if (p.pid === 1 || !byPid[p.ppid] || p.ppid === p.pid) roots.push(p);
        }
        roots.sort(function(a, b) { return (a.start_time || 0) - (b.start_time || 0); });
        for (i = 0; i < roots.length; ++i) walk(roots[i], 0);

        // Anything unreachable (a race between snapshot and walk) still gets shown
        // flat at the end rather than silently disappearing.
        for (i = 0; i < procs.length; ++i) {
            p = procs[i];
            if (p && !visited[p.pid]) {
                visited[p.pid] = true;
                if (anyFilter && !visibleByFilter[p.pid]) continue;
                out.push({ proc: p, depth: 0,
                           hasChildren: (childrenOf[p.pid] || []).length > 0,
                           isOpen: !!root.expanded[p.pid], matched: !!matching[p.pid] });
            }
        }

        root.rows = out;
    }

    onProcessesChanged: rebuild()
    onFilterChanged: rebuild()
    onExpandedChanged: rebuild()
    onShowKernelThreadsChanged: rebuild()
    Component.onCompleted: rebuild()

    // Header.
    Row {
        id: header
        anchors { left: parent.left; right: parent.right; top: parent.top }
        height: 26
        spacing: Theme.space2

        Rectangle {
            width: parent.width
            height: parent.height
            color: Theme.surfaceAlt
            radius: Theme.radiusSm

            Row {
                anchors { fill: parent; leftMargin: Theme.space3; rightMargin: Theme.space3 }
                spacing: Theme.space2

                Label {
                    text: qsTr("PROCESS"); width: parent.width * 0.40
                    color: Theme.textFaint; verticalAlignment: Text.AlignVCenter; height: parent.height
                    font { pixelSize: Theme.fontSizeMicro; family: Theme.fontFamily; weight: Theme.weightBold; letterSpacing: 1.0 }
                }
                Label {
                    text: "PID"; width: 52
                    color: Theme.textFaint; verticalAlignment: Text.AlignVCenter; height: parent.height
                    font { pixelSize: Theme.fontSizeMicro; family: Theme.fontFamily; weight: Theme.weightBold; letterSpacing: 1.0 }
                }
                Label {
                    text: "UID"; width: 44
                    color: Theme.textFaint; verticalAlignment: Text.AlignVCenter; height: parent.height
                    font { pixelSize: Theme.fontSizeMicro; family: Theme.fontFamily; weight: Theme.weightBold; letterSpacing: 1.0 }
                }
                Label {
                    text: "ST"; width: 26
                    color: Theme.textFaint; verticalAlignment: Text.AlignVCenter; height: parent.height
                    font { pixelSize: Theme.fontSizeMicro; family: Theme.fontFamily; weight: Theme.weightBold; letterSpacing: 1.0 }
                }
                Label {
                    text: qsTr("FLAGS"); width: parent.width * 0.28
                    color: Theme.textFaint; verticalAlignment: Text.AlignVCenter; height: parent.height
                    font { pixelSize: Theme.fontSizeMicro; family: Theme.fontFamily; weight: Theme.weightBold; letterSpacing: 1.0 }
                }
            }
        }
    }

    ListView {
        id: list
        anchors { left: parent.left; right: parent.right; top: header.bottom; bottom: parent.bottom }
        clip: true
        model: root.rows
        // Reuse delegates: 600 processes at 4 Hz is the exact case where delegate
        // churn shows up as dropped frames.
        reuseItems: true
        cacheBuffer: 400
        boundsBehavior: Flickable.StopAtBounds
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        delegate: Rectangle {
            id: row

            required property var modelData
            required property int index
            readonly property var proc: modelData.proc
            readonly property int depth: modelData.depth
            readonly property bool isOpen: modelData.isOpen
            readonly property bool hasChildren: modelData.hasChildren
            readonly property bool matched: modelData.matched

            width: ListView.view.width
            height: root.rowH
            color: rowMouse.containsMouse ? Theme.surfaceAlt
                 : row.matched ? Theme.withAlpha(Theme.accent, 0.07)
                 : (row.index % 2 === 1 ? Theme.withAlpha(Theme.surfaceAlt, 0.35) : "transparent")

            // Left rail showing ancestry depth. Thin lines, not indentation alone:
            // indentation stops being legible past about six levels, and a
            // container-escape lineage is exactly that deep.
            Row {
                id: rails
                anchors { left: parent.left; top: parent.top; bottom: parent.bottom }
                spacing: 0
                Repeater {
                    model: row.depth
                    Rectangle {
                        width: 14
                        color: "transparent"
                        Rectangle {
                            x: 6; width: 1; height: parent.height
                            color: Theme.borderSoft
                        }
                    }
                }
            }

            Row {
                anchors {
                    left: rails.right
                    right: parent.right
                    verticalCenter: parent.verticalCenter
                    leftMargin: Theme.space2
                    rightMargin: Theme.space3
                }
                spacing: Theme.space2

                // Expand chevron.
                Label {
                    text: row.hasChildren ? (row.isOpen ? "\u25BE" : "\u25B8") : "\u00B7"
                    width: 14
                    color: row.hasChildren ? Theme.textDim : Theme.border
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    height: parent.height
                    font.pixelSize: Theme.fontSizeSmall
                }

                // Frozen-by-us marker: the agent SIGSTOP'd this process, which is
                // the single most important thing to know about a row.
                GlowDot {
                    size: 8
                    anchors.verticalCenter: parent.verticalCenter
                    visible: String(row.proc.state).indexOf("T") === 0
                    color: Theme.high
                    glow: true
                    pulse: true
                }

                Column {
                    width: parent.width * 0.40 - 24
                    spacing: 0
                    anchors.verticalCenter: parent.verticalCenter

                    Label {
                        text: row.proc.comm || "?"
                        color: row.matched ? Theme.accent : Theme.text
                        font {
                            pixelSize: Theme.fontSizeBody
                            family: Theme.monoFamily
                            weight: row.matched ? Theme.weightBold : Theme.weightRegular
                        }
                        elide: Text.ElideRight
                        width: parent.width
                    }
                    Label {
                        text: Theme.elideMiddle(row.proc.exe, 62)
                        visible: (row.proc.exe || "").length > 0
                        color: Theme.textFaint
                        font.pixelSize: Theme.fontSizeMicro
                        font.family: Theme.monoFamily
                        elide: Text.ElideMiddle
                        width: parent.width
                    }
                }

                Label {
                    text: row.proc.pid
                    width: 52
                    color: Theme.textDim
                    verticalAlignment: Text.AlignVCenter
                    height: parent.height
                    font { pixelSize: Theme.fontSizeSmall; family: Theme.monoFamily }
                }
                Label {
                    text: row.proc.uid
                    width: 44
                    color: row.proc.uid === 0 ? Theme.medium : Theme.textFaint
                    verticalAlignment: Text.AlignVCenter
                    height: parent.height
                    font { pixelSize: Theme.fontSizeSmall; family: Theme.monoFamily }
                }
                Label {
                    text: row.proc.state
                    width: 26
                    color: Theme.sensorStateColor(row.proc.state === "T" ? "degraded"
                                                : row.proc.state === "Z" ? "failed" : "running")
                    verticalAlignment: Text.AlignVCenter
                    height: parent.height
                    font { pixelSize: Theme.fontSizeSmall; family: Theme.monoFamily; weight: Theme.weightBold }
                }

                // Flag chips.
                Row {
                    spacing: Theme.space1
                    width: parent.width * 0.28
                    height: parent.height
                    anchors.verticalCenter: parent.verticalCenter

                    Repeater {
                        model: {
                            var f = [];
                            if (row.proc.deleted_exe) f.push({ t: "DELETED-EXE", c: Theme.critical, why: "the executable was unlinked while running: classic fileless/in-memory execution" });
                            if (row.proc.suspicious_path) f.push({ t: "WRITABLE-PATH", c: Theme.high, why: "running from a world-writable location (/tmp, /dev/shm, a home dir)" });
                            if (row.proc.traced) f.push({ t: "TRACED", c: Theme.medium, why: "another process has ptrace attached: injection or debugging" });
                            if (row.proc.in_container || (row.proc.container || "").length > 0) f.push({ t: "CONTAINER", c: Theme.info, why: "inside " + (row.proc.container || "a container") });
                            if ((row.proc.cmdline || "").indexOf("sh -c") >= 0) f.push({ t: "SH -C", c: Theme.high, why: "shell spawned with an inline command" });
                            return f;
                        }

                        Rectangle {
                            required property var modelData
                            radius: Theme.radiusSm
                            height: 16
                            anchors.verticalCenter: parent.verticalCenter
                            width: chipLabel.width + Theme.space2
                            color: Theme.withAlpha(modelData.c, 0.15)
                            border.width: 1
                            border.color: Theme.withAlpha(modelData.c, 0.5)

                            Label {
                                id: chipLabel
                                anchors.centerIn: parent
                                text: modelData.t
                                color: modelData.c
                                font { pixelSize: 8; family: Theme.fontFamily; weight: Theme.weightBold; letterSpacing: 0.6 }
                            }
                            ToolTip.visible: chipHover.containsMouse
                            ToolTip.text: modelData.why
                            ToolTip.delay: 250
                            HoverHandler { id: chipHover }
                        }
                    }
                }
            }

            HoverHandler { id: rowMouse }
            TapHandler {
                onSingleTapped: {
                    if (row.hasChildren) root.toggle(row.proc.pid);
                    root.rowClicked(row.proc);
                }
                onDoubleTapped: root.rowDoubleClicked(row.proc)
            }

            // Right-click context menu: the actions an analyst wants on a suspect.
            TapHandler {
                acceptedButtons: Qt.RightButton
                onTapped: rowMenu.openFor(row.proc)
            }
        }
    }

    Menu {
        id: rowMenu
        property var target: null
        function openFor(proc) { target = proc; popup(); }

        MenuItem {
            text: qsTr("Investigate (full escalation pipeline)")
            enabled: rowMenu.target !== null
            onTriggered: if (rowMenu.target) root.investigateRequested(rowMenu.target.pid)
        }
        MenuItem {
            text: qsTr("Freeze (SIGSTOP)")
            enabled: rowMenu.target !== null
            onTriggered: if (rowMenu.target) backend.suspend(rowMenu.target.pid)
        }
        MenuItem {
            text: qsTr("Resume (SIGCONT)")
            enabled: rowMenu.target !== null
            onTriggered: if (rowMenu.target) backend.resume(rowMenu.target.pid)
        }
        MenuSeparator {}
        MenuItem {
            text: qsTr("Scan executable on demand")
            enabled: rowMenu.target !== null && (rowMenu.target.exe || "").length > 0
            onTriggered: if (rowMenu.target) backend.scanPath(rowMenu.target.exe)
        }
        MenuItem {
            text: qsTr("Inspect memory (Module 4c)")
            enabled: rowMenu.target !== null
            onTriggered: if (rowMenu.target) backend.inspectMemory(rowMenu.target.pid)
        }
        MenuItem {
            text: qsTr("Advanced scan (engine + VirusTotal ladder)")
            enabled: rowMenu.target !== null && (rowMenu.target.exe || "").length > 0
            onTriggered: if (rowMenu.target) backend.advancedScan(rowMenu.target.exe)
        }
        MenuItem {
            text: qsTr("Quarantine executable")
            enabled: rowMenu.target !== null && (rowMenu.target.exe || "").length > 0
            onTriggered: if (rowMenu.target) backend.quarantine(rowMenu.target.exe)
        }
    }

    EmptyState {
        anchors.centerIn: list
        visible: list.count === 0
        good: true
        message: root.filter.length > 0 ? qsTr("No process matches \u201C%1\u201D").arg(root.filter)
                                        : qsTr("No processes in the snapshot")
        hint: root.filter.length > 0 ? qsTr("Filters also reveal the ancestors of a match") : ""
    }
}
