// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 7 — console shell
//
// ApplicationWindow + navigation rail + top bar + a Loader per page + status bar.
//
// The three structural decisions here are about frame budget, because the console
// runs beside a detection agent on the same host and is expected to stay open for
// days on a wall monitor:
//
//   1. ONE PAGE ALIVE AT A TIME. Each page is a Loader whose `active` is bound to
//      "am I the current page". Nine pages each holding a 720-point history array,
//      a ListView of 2000 events and several Canvases is the difference between
//      120 MB and 30 MB of RSS and between 60 fps and 20. Navigating away destroys
//      the page; navigating back rebuilds it from the backend's cached snapshot,
//      which is already in memory and costs one property read.
//
//   2. NO POLLING WHILE HIDDEN. `active` on the window gates every refresh timer.
//      An operator who leaves the console on a second monitor and walks away should
//      not pay for four refreshes a second forever. The agent is unaffected: it
//      detects and acts on its own, and the console catches up in one round trip
//      when it becomes visible again.
//
//   3. THE SHELL NEVER BLOCKS. Every backend call is a Q_INVOKABLE that writes to a
//      socket and returns; replies arrive as signals. There is no synchronous path
//      from a button click to the render thread, which is the whole reason the UI
//      cannot stutter when the agent is busy.
//
// Navigation is Ctrl+1..9 and Alt+arrows, because a console operated during an
// incident is often operated with one hand on the keyboard and the other on a phone.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import "theme"
import "components"

ApplicationWindow {
    id: window

    // ---- identity -----------------------------------------------------------
    visible: true
    width: 1480
    height: 900
    minimumWidth: 1024
    minimumHeight: 640
    // VIBRANCY: the window itself is transparent and the chrome sits on a rounded,
    // semi-transparent base plate (`Theme.base`), so a compositor shows the
    // desktop through the shell. Everything drawn ON the plate (cards, text,
    // controls) is fully opaque -- translucency under content is unreadable and
    // is exactly what the reference design avoids. Without a compositor Qt
    // ignores the alpha and the shell simply renders opaque. The frameless hint
    // comes with our own window controls (top bar, right) and drag handling.
    readonly property bool vibrancy: typeof windowVibrancy !== "undefined" ? windowVibrancy : true
    flags: vibrancy ? Qt.Window | Qt.FramelessWindowHint : Qt.Window
    color: "transparent"
    title: backend.connected
           ? qsTr("HyprNova Anti-Malware Sec \u2014 %1 \u2014 posture %2/100")
                 .arg(backend.version.length > 0 ? backend.version : qsTr("agent"))
                 .arg(backend.postureScore)
           : qsTr("HyprNova Anti-Malware Sec \u2014 agent not connected")

    /// Global search text, set from the top-bar SearchBox and consumed by the
    /// Threats page filter on commit.
    property string searchQuery: ""

    /// Current page index. Persisted across reconnects but not across restarts:
    /// an operator who left the console on Threats wants Threats, but a fresh
    /// session should always start at the Dashboard, which is the triage entry
    /// point and the only page that summarises everything else.
    property int pageIndex: 0

    /// Page registry. Kept as data rather than as nine hard-coded Loaders so adding
    /// a page is one array entry, and so the nav rail, the shortcut handler and the
    /// Loader stack cannot drift out of sync with each other.
    readonly property var pages: [
        { name: qsTr("Home"),        icon: "home",       src: "pages/DashboardPage.qml" },
        { name: qsTr("Threats"),     icon: "shield",     src: "pages/ThreatsPage.qml",     badge: "alerts" },
        { name: qsTr("Processes"),   icon: "processes",  src: "pages/ProcessesPage.qml" },
        { name: qsTr("Network"),     icon: "network",    src: "pages/NetworkPage.qml",     badge: "beacons" },
        { name: qsTr("Scanning"),    icon: "scan",       src: "pages/ScanningPage.qml" },
        { name: qsTr("Hardening"),   icon: "hardening",  src: "pages/HardeningPage.qml" },
        { name: qsTr("Canaries"),    icon: "canaries",   src: "pages/CanariesPage.qml" },
        { name: qsTr("Remediation"), icon: "remediation",src: "pages/RemediationPage.qml", badge: "blocks" },
        { name: qsTr("Tools"),       icon: "tools",      src: "pages/ToolsPage.qml" },
        { name: qsTr("Memory"),      icon: "scan",       src: "pages/MemoryPage.qml" },
        { name: qsTr("AI analyst"),  icon: "home",       src: "pages/AiAnalystPage.qml" },
        { name: qsTr("Integrations"),icon: "tools",      src: "pages/IntegrationsPage.qml" },
        { name: qsTr("Backups"),     icon: "hardening",  src: "pages/BackupsPage.qml" },
        { name: qsTr("Recovery"),    icon: "remediation",src: "pages/FileRecoveryPage.qml" },
        { name: qsTr("Timeline"),    icon: "home",       src: "pages/TimelinePage.qml" },
        { name: qsTr("Settings"),    icon: "settings",   src: "pages/SettingsPage.qml" }
    ]

    /// Counters shown as nav badges. Recomputed only when the underlying property
    /// changes, never on a timer of their own.
    readonly property int alertCount: backend.pendingDecisions
    readonly property int beaconCount: backend.beacons.length
    readonly property int blockCount: backend.activeBlocks

    // ---- refresh scheduling -------------------------------------------------
    //
    // One timer drives the whole console. `refreshHz` is a context property read
    // from the agent config in gui_app.cpp (clamped 1..10 there), so the operator's
    // configured rate is honoured
    // rather than hard-coded here — and if the agent is on a small VM, lowering
    // telemetry_hz is the single knob that reduces console CPU.
    //
    // The refresh is split: a fast path (overview + events + risk) that must never
    // lag, and a slow path (processes, network, scans, hardening, canaries) that
    // runs every fourth tick. Processes and connections are the two largest
    // payloads by an order of magnitude, and nothing in an operator's reading of
    // them benefits from 4 Hz.
    Timer {
        id: fastTick
        interval: Math.max(100, Math.round(1000 / Math.max(1, backend.refreshHz)))
        repeat: true
        running: backend.connected && window.visible && !window.suspended
        triggeredOnStart: true
        onTriggered: {
            backend.refreshOverview();
            if (window.pageIndex === 0 || window.pageIndex === 1) {
                backend.refreshEvents(200);
                backend.refreshRisk();
                backend.refreshDecisions();
            }
            slowCounter++;
            if (slowCounter % 4 === 0) slowTickTriggered();
        }
        property int slowCounter: 0
        signal slowTickTriggered
    }

    Connections {
        target: fastTick
        function onSlowTickTriggered() {
            // Only ask for what the current page will actually draw. This is the
            // single biggest saving in the console: an idle Dashboard stops
            // requesting a 600-process snapshot entirely.
            switch (window.pageIndex) {
            case 2: backend.refreshProcesses(400); backend.refreshSensors(); break;
            case 3: backend.refreshNetwork(); break;
            case 4: backend.refreshScans(); backend.refreshProcesses(100); break;
            case 5: backend.refreshHardening(); backend.refreshBaseline(); break;
            case 6: backend.refreshCanaries(); break;
            case 7: backend.refreshRemediation(); break;
            case 8: backend.refreshToolbox(); break;
            case 9: backend.refreshSensors(); backend.refreshBaseline(); break;
            default: backend.refreshSensors(); break;
            }
        }
    }

    // Full refresh on reconnect and on becoming visible again, so a console that
    // was hidden for an hour does not show a stale posture score for one tick.
    Connections {
        target: backend
        function onConnectedChanged() {
            if (backend.connected) {
                backend.refreshAll();
                toasts.push("info", qsTr("Connected to agent"), agentSocket);
            } else {
                toasts.push("critical", qsTr("Lost connection to the agent"),
                            backend.connectionError.length > 0 ? backend.connectionError
                                                                 : qsTr("Detection continues without the console."));
            }
        }
    }

    Connections {
        target: window
        function onVisibleChanged() { if (window.visible) backend.refreshAll(); }
    }

    // ---- agent -> operator signals ------------------------------------------
    Connections {
        target: backend

        /// The escalation prompt. This is the only thing in the console allowed to
        /// take focus away from the operator.
        function onDecisionRequired(decision) {
            threatDialog.decision = decision;
            threatDialog.open();
            toasts.push(decision.report && decision.report.severity ? decision.report.severity : "high",
                        qsTr("Escalation waiting on you"),
                        decision.recommendation ? qsTr("recommendation: %1").arg(decision.recommendation) : "");
        }

        function onActionCompleted(action) {
            var outcome = String(action.outcome || "");
            var sev = outcome === "ok" || outcome === "applied" ? "low"
                    : outcome === "denied" || outcome === "skipped" ? "medium"
                    : outcome === "failed" ? "high" : "info";
            var what = String(action.action || "action");
            var where = String(action.target || (action.pid ? "pid " + action.pid : ""));
            toasts.push(sev, qsTr("%1: %2").arg(what.charAt(0).toUpperCase() + what.slice(1)).arg(outcome),
                        [where, action.detail || ""].filter(function(s) { return s.length > 0; }).join(" \u2014 "));
        }

        function onNotice(severity, message) {
            toasts.push(severity, message, "");
        }

        function onInvestigationFinished(report) {
            // An operator-initiated investigation returns a report but no decision
            // row, so it gets its own read-only presentation of the same dialog.
            threatDialog.decision = { id: 0, raised: Math.floor(Date.now() / 1000),
                                      recommendation: "", answered: false,
                                      report: report, factors: report.factors || [],
                                      actions: ["allow", "quarantine", "kill"] };
            threatDialog.open();
        }
    }

    /// True when the operator has explicitly paused refresh (top-bar control).
    property bool suspended: false

    // ============================== LAYOUT ====================================

    // ---- base plate ----
    // The rounded, semi-transparent plate everything lives on when vibrancy is
    // on (see the window block). `clip` is what makes the frameless rounded
    // corners work: the chrome rectangles are rectangular, and their corner
    // overflow is cut by this clip instead of poking past the radius.
    Rectangle {
        id: basePlate
        anchors.fill: parent
        radius: window.vibrancy ? Theme.windowRadius : 0
        color: window.vibrancy ? Theme.base : Theme.bg
        border.width: window.vibrancy ? 1 : 0
        border.color: Theme.withAlpha(Theme.text, 0.07)
        clip: true

        // The rail, top bar, page stack, status bar and toasts are declared
        // INSIDE this plate: real nesting (not a runtime reparent) keeps every
        // sibling anchor valid at creation time and lets `clip` trim the
        // rectangular chrome at the rounded corners.

    // ---- navigation rail ----
    Rectangle {
        id: rail
        anchors { left: parent.left; top: parent.top; bottom: statusBar.top }
        width: Theme.sidebarWidth
        color: Theme.surface
        z: 2

        Rectangle { anchors { right: parent.right; top: parent.top; bottom: parent.bottom } width: 1; color: Theme.border }

        ColumnLayout {
            anchors { fill: parent }
            spacing: 0

            // Brand block.
            Item {
                Layout.fillWidth: true
                Layout.preferredHeight: Theme.topbarHeight

                RowLayout {
                    anchors { fill: parent; leftMargin: Theme.space4; rightMargin: Theme.space3 }
                    spacing: Theme.space2

                    // Mark: the reference-style logo tile — rounded brand-green
                    // square, white shield glyph, live status dot. Drawn, not an
                    // image asset: no scaling bug and nothing binary in the repo.
                    Item {
                        Layout.preferredWidth: 34
                        Layout.preferredHeight: 34
                        Layout.alignment: Qt.AlignVCenter

                        Rectangle {
                            anchors.fill: parent
                            radius: 9
                            color: backend.connected ? Theme.accent : Theme.surfaceAlt
                            Behavior on color { ColorAnimation { duration: Theme.animNormal } }
                        }
                        NavIcon {
                            name: "shield"
                            color: backend.connected ? "#FFFFFF" : Theme.textFaint
                            width: 19; height: 19
                            anchors.centerIn: parent
                        }
                        GlowDot {
                            size: 7
                            color: backend.connected ? Theme.ok : Theme.down
                            glow: !backend.connected
                            pulse: !backend.connected
                            anchors { right: parent.right; bottom: parent.bottom; margins: -1 }
                        }
                    }
                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.alignment: Qt.AlignVCenter
                        spacing: 0
                        Row {
                            spacing: 0
                            Layout.alignment: Qt.AlignVCenter
                            Label {
                                text: "HYP"
                                color: Theme.accent
                                font {
                                    pixelSize: Theme.fontSizeLarge
                                    family: Theme.fontFamily
                                    weight: Theme.weightBold
                                    letterSpacing: 2.6
                                }
                            }
                            Label {
                                text: "NOVA"
                                color: Theme.text
                                font {
                                    pixelSize: Theme.fontSizeLarge
                                    family: Theme.fontFamily
                                    weight: Theme.weightBold
                                    letterSpacing: 2.6
                                }
                            }
                        }
                        Label {
                            text: qsTr("Anti-Malware Sec")
                            color: Theme.textFaint
                            font { pixelSize: Theme.fontSizeMicro; family: Theme.fontFamily; letterSpacing: 0.6 }
                        }
                    }
                }
            }

            Rectangle { Layout.fillWidth: true; height: 1; color: Theme.border }

            // Nav items.
            ListView {
                id: nav
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.topMargin: Theme.space2
                model: window.pages
                interactive: false
                clip: true

                delegate: Item {
                    id: navItem

                    required property var modelData
                    required property int index
                    readonly property bool current: window.pageIndex === index

                    width: ListView.view.width
                    height: 40

                    Rectangle {
                        id: rowBg
                        anchors {
                            left: parent.left; right: parent.right
                            top: parent.top
                            bottom: parent.bottom
                            topMargin: 2
                            leftMargin: Theme.space2
                            rightMargin: Theme.space2
                        }
                        // Reference-style nav: the active item is a LIGHTER grey
                        // pill with white text, not a tinted brand colour — the
                        // brand green stays reserved for status and actions.
                        radius: 8
                        color: navItem.current ? Theme.surfaceAlt
                             : navHover.containsMouse ? Theme.withAlpha(Theme.text, 0.05) : "transparent"
                        Behavior on color { ColorAnimation { duration: Theme.animFast } }

                        RowLayout {
                            anchors { fill: parent; leftMargin: Theme.space3; rightMargin: Theme.space2 }
                            spacing: Theme.space3

                            NavIcon {
                                name: navItem.modelData.icon
                                color: navItem.current ? Theme.text : Theme.textFaint
                                Layout.preferredWidth: 18
                                Layout.preferredHeight: 18
                                Layout.alignment: Qt.AlignVCenter
                            }
                            Label {
                                text: navItem.modelData.name
                                color: navItem.current ? Theme.text : Theme.textDim
                                font {
                                    pixelSize: Theme.fontSizeBody
                                    family: Theme.fontFamily
                                    weight: navItem.current ? Theme.weightBold : Theme.weightRegular
                                }
                                Layout.fillWidth: true
                                elide: Text.ElideRight
                                Layout.alignment: Qt.AlignVCenter
                            }
                            // Badge: only where a non-zero count means "act on this".
                            Rectangle {
                                visible: navBadge.count > 0
                                Layout.preferredWidth: Math.max(18, navBadge.implicitWidth + Theme.space2)
                                Layout.preferredHeight: 16
                                Layout.alignment: Qt.AlignVCenter
                                radius: Theme.radiusPill
                                color: navBadge.sev === "critical" ? Theme.critical
                                     : navBadge.sev === "high" ? Theme.high : Theme.accent

                                Label {
                                    id: navBadge
                                    anchors.centerIn: parent
                                    // Counts past 99 become "99+"; a wider pill would
                                    // push the label out of the 216 px rail.
                                    readonly property int count: {
                                        switch (navItem.modelData.badge) {
                                        case "alerts":   return window.alertCount;
                                        case "beacons":  return window.beaconCount;
                                        case "blocks":   return window.blockCount;
                                        default:         return 0;
                                        }
                                    }
                                    readonly property string sev: {
                                        switch (navItem.modelData.badge) {
                                        case "alerts":  return "critical";
                                        case "beacons": return "high";
                                        default:        return "info";
                                        }
                                    }
                                    text: count > 99 ? "99+" : String(count)
                                    color: Theme.textOnAccent
                                    font {
                                        pixelSize: Theme.fontSizeMicro
                                        family: Theme.monoFamily
                                        weight: Theme.weightBold
                                    }
                                }

                                SequentialAnimation on opacity {
                                    running: navBadge.sev === "critical" && navBadge.count > 0 && navItem.visible
                                    loops: Animation.Infinite
                                    NumberAnimation { to: 0.55; duration: Theme.pulseMs / 2; easing.type: Easing.InOutSine }
                                    NumberAnimation { to: 1.0;  duration: Theme.pulseMs / 2; easing.type: Easing.InOutSine }
                                }
                            }
                        }
                    }

                    HoverHandler { id: navHover }
                    TapHandler { onTapped: { window.goTo(navItem.index); } }

                    // Keyboard: the rail items are focusable so the console is
                    // operable without a pointing device, which matters on a server
                    // console reached over a serial link or a KVM.
                    Keys.onReturnPressed: window.goTo(navItem.index)
                }
            }

            // Rail footer: the two things an operator needs to see from any page.
            Rectangle {
                Layout.fillWidth: true
                height: 1
                color: Theme.border
            }
            Item {
                Layout.fillWidth: true
                Layout.preferredHeight: footerCol.height + Theme.space4

                ColumnLayout {
                    id: footerCol
                    anchors {
                        left: parent.left; right: parent.right; verticalCenter: parent.verticalCenter
                        leftMargin: Theme.space4; rightMargin: Theme.space4
                    }
                    spacing: Theme.space2

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space2
                        GlowDot {
                            size: 8
                            color: backend.learning ? Theme.medium : Theme.ok
                            glow: backend.learning
                            pulse: backend.learning
                        }
                        Label {
                            text: backend.learning
                                  ? qsTr("Learning baseline %1%").arg(Math.round(backend.learningProgress * 100))
                                  : qsTr("Baseline established")
                            color: Theme.textDim
                            font.pixelSize: Theme.fontSizeSmall
                            Layout.fillWidth: true
                            elide: Text.ElideRight
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space2
                        GlowDot {
                            size: 8
                            color: backend.autoRespond ? Theme.ok : Theme.medium
                            glow: false
                        }
                        Label {
                            text: backend.autoRespond ? qsTr("Auto-respond ON") : qsTr("Auto-respond OFF")
                            color: Theme.textDim
                            font.pixelSize: Theme.fontSizeSmall
                            Layout.fillWidth: true
                            elide: Text.ElideRight
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space2
                        visible: backend.dryRun
                        GlowDot { size: 8; color: Theme.high; glow: true; pulse: true }
                        Label {
                            text: qsTr("DRY RUN \u2014 no action will be taken")
                            color: Theme.high
                            font { pixelSize: Theme.fontSizeSmall; weight: Theme.weightBold }
                            Layout.fillWidth: true
                            elide: Text.ElideRight
                        }
                    }
                }
            }
        }
    }

    // ---- top bar ----
    Rectangle {
        id: topbar
        anchors { left: rail.right; right: parent.right; top: parent.top }
        height: Theme.topbarHeight
        color: "transparent"          // the base plate shows through: vibrancy
        z: 1

        Rectangle { anchors { left: parent.left; right: parent.right; bottom: parent.bottom } height: 1; color: Theme.border }

        // Drag-to-move for the frameless window. Declared before the content and
        // given no hover stealing: empty top-bar areas drag the window, controls
        // on top keep their clicks. Double-click toggles maximise.
        MouseArea {
            anchors.fill: parent
            z: -1
            cursorShape: Qt.SizeAllCursor
            onPressed: window.startSystemMove()
            onDoubleClicked: window.vibrancy && (window.visibility === Window.Maximized)
                             ? window.showNormal() : window.showMaximized()
        }

        RowLayout {
            anchors { fill: parent; leftMargin: Theme.space4; rightMargin: Theme.space4 }
            spacing: Theme.space4

            SearchBox {
                id: searchBox
                Layout.alignment: Qt.AlignVCenter
                onSearchCommitted: function(text) {
                    // One honest destination: the Threats feed, filtered.
                    window.searchQuery = text;
                    window.goTo(1);
                    toasts.push("info", text.length > 0 ? qsTr("Filtering Threats by '%1'").arg(text)
                                                        : qsTr("Search filter cleared"), "");
                }
            }

            // Posture score. The single most important number in the product: it is
            // what a manager looks at and what an analyst checks first.
            RowLayout {
                spacing: Theme.space3
                Layout.alignment: Qt.AlignVCenter

                ColumnLayout {
                    spacing: 0
                    Layout.alignment: Qt.AlignVCenter
                    Label {
                        text: qsTr("POSTURE")
                        color: Theme.textFaint
                        font { pixelSize: Theme.fontSizeMicro; family: Theme.fontFamily; weight: Theme.weightBold; letterSpacing: 1.2 }
                    }
                    Label {
                        text: backend.postureLabel
                        color: Theme.riskColor((100 - backend.postureScore) * 10)
                        font { pixelSize: Theme.fontSizeSmall; family: Theme.fontFamily; weight: Theme.weightMedium }
                    }
                }

                Label {
                    text: backend.postureScore
                    color: Theme.riskColor((100 - backend.postureScore) * 10)
                    font {
                        pixelSize: Theme.fontSizeHero - 10
                        family: Theme.monoFamily
                        weight: Theme.weightBold
                    }
                    Layout.alignment: Qt.AlignVCenter
                }
                Label {
                    text: "/100"
                    color: Theme.textFaint
                    font.pixelSize: Theme.fontSizeSmall
                    font.family: Theme.monoFamily
                    Layout.alignment: Qt.AlignBottom
                    Layout.bottomMargin: 6
                }
            }

            Rectangle { Layout.preferredWidth: 1; Layout.preferredHeight: 32; color: Theme.border }

            // Sensor health at a glance: running / degraded. Degraded is not an
            // error state — it means a dependency is missing and coverage is
            // partial, which is the honest thing to show.
            RowLayout {
                spacing: Theme.space2
                Layout.alignment: Qt.AlignVCenter
                GlowDot {
                    size: 9
                    color: backend.sensorsDegraded > 0 ? Theme.medium : Theme.ok
                    glow: backend.sensorsDegraded > 0
                }
                Label {
                    text: qsTr("%1 sensors up").arg(backend.sensorsRunning)
                          + (backend.sensorsDegraded > 0 ? qsTr(", %1 degraded").arg(backend.sensorsDegraded) : "")
                    color: backend.sensorsDegraded > 0 ? Theme.medium : Theme.textDim
                    font.pixelSize: Theme.fontSizeSmall
                }
            }

            Rectangle { Layout.preferredWidth: 1; Layout.preferredHeight: 32; color: Theme.border }

            // Live risk summary.
            RowLayout {
                spacing: Theme.space2
                Layout.alignment: Qt.AlignVCenter
                Label {
                    text: qsTr("top risk")
                    color: Theme.textFaint
                    font.pixelSize: Theme.fontSizeMicro
                }
                RiskBar {
                    risk: backend.riskSummary.top_score || 0
                    compact: true
                    Layout.preferredWidth: 72
                    Layout.preferredHeight: 6
                    Layout.alignment: Qt.AlignVCenter
                }
                Label {
                    text: Math.round(backend.riskSummary.top_score || 0)
                    color: Theme.riskColor(backend.riskSummary.top_score || 0)
                    font { pixelSize: Theme.fontSizeSmall; family: Theme.monoFamily; weight: Theme.weightBold }
                }
            }

            Item { Layout.fillWidth: true }

            // Frozen / blocked counters. These are the two states where the agent is
            // actively holding something down, so they are always visible: an
            // operator who forgot a process is frozen has caused an outage.
            NovaButton {
                visible: backend.suspendedPids > 0
                text: qsTr("%1 frozen").arg(backend.suspendedPids)
                role: "danger"
                compact: true
                glyph: "\u23F8"
                onTriggered: { window.goTo(7); }
                ToolTip.visible: hovered
                ToolTip.text: qsTr("Processes the agent has SIGSTOP'd. Click to review and release them.")
            }
            NovaButton {
                visible: backend.activeBlocks > 0
                text: qsTr("%1 blocked").arg(backend.activeBlocks)
                role: "secondary"
                compact: true
                glyph: "\u29B8"
                onTriggered: { window.goTo(7); }
                ToolTip.visible: hovered
                ToolTip.text: qsTr("nftables rules the agent is enforcing. Click to review TTLs and unblock.")
            }

            NovaButton {
                text: window.suspended ? qsTr("Resume feed") : qsTr("Pause feed")
                role: window.suspended ? "primary" : "ghost"
                compact: true
                glyph: window.suspended ? "\u25B6" : "\u23F8"
                onTriggered: {
                    window.suspended = !window.suspended;
                    toasts.push(window.suspended ? "medium" : "low",
                                window.suspended ? qsTr("Console refresh paused")
                                                 : qsTr("Console refresh resumed"),
                                window.suspended ? qsTr("The agent keeps detecting and acting; only this display is frozen.") : "");
                }
                ToolTip.visible: hovered
                ToolTip.text: qsTr("Stop refreshing the display. Detection is never paused from here.")
            }

            NovaButton {
                text: qsTr("Refresh")
                role: "ghost"
                compact: true
                glyph: "\u21BB"
                onTriggered: backend.refreshAll()
                ToolTip.visible: hovered
                ToolTip.text: qsTr("Pull every snapshot from the agent now (Ctrl+R)")
            }

            Item { Layout.fillWidth: true }

            // Help: answers "what am I looking at" without a modal. The full
            // About story lives in Settings.
            AbstractButton {
                id: helpBtn
                width: 30; height: 30
                Layout.alignment: Qt.AlignVCenter
                background: Rectangle {
                    radius: 15
                    color: helpBtn.hovered ? Theme.surfaceAlt : "transparent"
                }
                contentItem: NavIcon {
                    name: "help"
                    color: helpBtn.hovered ? Theme.text : Theme.textDim
                    width: 16; height: 16
                    anchors.centerIn: parent
                }
                onClicked: toasts.push("info", qsTr("%1 v%2").arg("HyprNova Anti-Malware Sec").arg(guiVersion),
                                       qsTr("agent socket: %1").arg(agentSocket));
            }

            // ---- window controls (frameless only; the system draws its own
            // decorations otherwise) ----
            RowLayout {
                visible: window.vibrancy
                spacing: 2
                Layout.alignment: Qt.AlignVCenter

                Repeater {
                    model: [
                        { icon: "minimize", act: "min" },
                        { icon: "maximize", act: "max" },
                        { icon: "close",    act: "close" }
                    ]

                    delegate: AbstractButton {
                        id: winBtn
                        required property var modelData
                        width: 34; height: 28
                        hoverEnabled: true
                        background: Rectangle {
                            radius: 6
                            color: winBtn.modelData.act === "close" && winBtn.hovered ? "#C94057"
                                 : winBtn.hovered ? Theme.surfaceAlt : "transparent"
                        }
                        contentItem: NavIcon {
                            name: winBtn.modelData.icon
                            color: winBtn.modelData.act === "close" && winBtn.hovered ? "#FFFFFF"
                                 : winBtn.hovered ? Theme.text : Theme.textDim
                            width: 13; height: 13
                            anchors.centerIn: parent
                        }
                        onClicked: {
                            if (winBtn.modelData.act === "min") window.showMinimized();
                            else if (winBtn.modelData.act === "max") {
                                if (window.visibility === Window.Maximized) window.showNormal();
                                else window.showMaximized();
                            } else window.close();
                        }
                    }
                }
            }
        }
    }

    // ---- page stack ----
    Item {
        id: pageArea
        anchors { left: rail.right; right: parent.right; top: topbar.bottom; bottom: statusBar.top }

        Repeater {
            model: window.pages

            delegate: Loader {
                id: pageLoader

                required property int index
                required property var modelData

                // Only the current page exists. See decision 1 in the header
                // comment: nine live pages is a different product on a 2 GB VM.
                active: window.pageIndex === index
                visible: active
                // Anchors are bound to `active` rather than set unconditionally:
                // eight invisible zero-size Loaders stacked over the live one would
                // still be item siblings at full size, and a Loader with no source
                // has implicitWidth 0 only when it is not anchored to the parent.
                anchors.fill: active ? parent : undefined
                asynchronous: false   // synchronous: the snapshot is already in memory
                source: modelData.src

                // Every page gets the same two context values so it does not have to
                // re-derive them.
                onLoaded: {
                    if (item && item.hasOwnProperty("pageIndex")) item.pageIndex = index;
                }
            }
        }

        // ---- disconnected veil ----
        //
        // Shown instead of an empty page. The wording is deliberate: the console
        // being down does NOT mean the host is unprotected, and an operator who
        // reads "disconnected" as "unmonitored" makes the wrong call.
        Rectangle {
            anchors.fill: parent
            color: Theme.withAlpha(Theme.bg, 0.94)
            visible: !backend.connected
            z: 5

            EmptyState {
                anchors.centerIn: parent
                good: false
                message: qsTr("Not connected to the HyprNova agent")
                hint: backend.connectionError.length > 0
                      ? backend.connectionError
                      : qsTr("Socket: %1").arg(agentSocket)

                NovaButton {
                    text: qsTr("Retry now")
                    role: "primary"
                    onTriggered: backend.refreshAll()
                }
                NovaButton {
                    text: qsTr("Open settings")
                    role: "secondary"
                    onTriggered: { window.goTo(9); }
                }
            }

            // Three-line diagnostic, because "it does not connect" is the most
            // common support question and the answer is almost always one of these.
            ColumnLayout {
                anchors { horizontalCenter: parent.horizontalCenter; bottom: parent.bottom; bottomMargin: Theme.space6 }
                spacing: Theme.space1
                Repeater {
                    model: [
                        qsTr("1. Is the agent running?   systemctl status hyprnovad"),
                        qsTr("2. Is the socket there?      ls -l %1").arg(agentSocket),
                        qsTr("3. Are you root, or in the group that owns it?   The bridge authorises on SO_PEERCRED.")
                    ]
                    Label {
                        required property string modelData
                        text: modelData
                        color: Theme.textFaint
                        font.pixelSize: Theme.fontSizeSmall
                        font.family: Theme.monoFamily
                        Layout.alignment: Qt.AlignHCenter
                    }
                }
            }
        }
    }

    // ---- status bar ----
    Rectangle {
        id: statusBar
        anchors { left: parent.left; right: parent.right; bottom: parent.bottom }
        height: Theme.statusbarHeight
        color: Theme.surface
        z: 3

        Rectangle { anchors { left: parent.left; right: parent.right; top: parent.top } height: 1; color: Theme.border }

        RowLayout {
            anchors { fill: parent; leftMargin: Theme.space4; rightMargin: Theme.space4 }
            spacing: Theme.space4

            Label {
                text: window.pages[window.pageIndex].name
                color: Theme.textDim
                font { pixelSize: Theme.fontSizeSmall; family: Theme.fontFamily; weight: Theme.weightMedium }
            }
            Label {
                text: backend.connected ? agentSocket : qsTr("offline")
                color: Theme.textFaint
                font.pixelSize: Theme.fontSizeMicro
                font.family: Theme.monoFamily
                elide: Text.ElideMiddle
                Layout.maximumWidth: 320
            }

            Item { Layout.fillWidth: true }

            // Throughput and drops. `dropped` is surfaced permanently rather than
            // only in an alert, because a console that silently loses events is
            // worse than one that admits it: the bus drops rather than back-pressures
            // the detection path, which is the correct trade and must be visible.
            Label {
                text: qsTr("events %1").arg(window.formatCount(backend.eventsPublished))
                color: Theme.textFaint
                font.pixelSize: Theme.fontSizeMicro
                font.family: Theme.monoFamily
            }
            Label {
                text: qsTr("dropped %1").arg(window.formatCount(backend.eventsDropped))
                color: backend.eventsDropped > 0 ? Theme.high : Theme.textFaint
                font.pixelSize: Theme.fontSizeMicro
                font.family: Theme.monoFamily
            }
            Label {
                text: qsTr("%1 Hz").arg(refreshHz)
                color: Theme.textFaint
                font.pixelSize: Theme.fontSizeMicro
                font.family: Theme.monoFamily
            }
            Label {
                text: qsTr("up %1").arg(Theme.formatUptime(backend.uptime))
                color: Theme.textFaint
                font.pixelSize: Theme.fontSizeMicro
                font.family: Theme.monoFamily
            }
            Label {
                text: "v" + guiVersion
                color: Theme.textFaint
                font.pixelSize: Theme.fontSizeMicro
                font.family: Theme.monoFamily
            }
        }
    }

    // ---- overlays ----
    ToastStack {
        id: toasts
        anchors.fill: parent
        z: 20
    }
    }  // basePlate

    ThreatDialog {
        id: threatDialog
        z: 30
        onAnswered: function(id, action) {
            if (id > 0) {
                backend.answer(id, action);
                toasts.push(action === "kill" || action === "quarantine" ? "high" : "low",
                            qsTr("Decision recorded: %1").arg(action),
                            id > 0 ? qsTr("decision #%1").arg(id) : "");
            } else {
                // id 0 == an operator-initiated investigation with no pending
                // decision; the actions go straight to the process endpoints.
                var pid = threatDialog.report ? threatDialog.report.pid : 0;
                if (pid > 0) {
                    if (action === "allow") backend.resume(pid);
                    else if (action === "kill") backend.kill(pid);
                    else if (action === "quarantine") backend.quarantine(threatDialog.report.exe);
                }
            }
            backend.refreshDecisions();
            backend.refreshRemediation();
        }
    }

    // ---- navigation plumbing ----
    /// Open the escalation dialog for a specific decision. Called from pages
    /// (ThreatsPage) that have a decision row in hand but are not the shell, so
    /// they reach the dialog through the attached Window rather than an id.
    function threatDialogOpen(decision) {
        threatDialog.decision = decision;
        threatDialog.open();
    }

    function goTo(i) {
        if (i < 0 || i >= pages.length) return;
        if (i === pageIndex) return;
        pageIndex = i;
        // Immediately pull the snapshot the new page needs rather than waiting up to
        // a second for the next slow tick: perceived latency on navigation is the
        // thing users actually notice.
        switch (i) {
        case 0: backend.refreshOverview(); backend.refreshEvents(200); backend.refreshRisk(); break;
        case 1: backend.refreshEvents(400); backend.refreshRisk(); backend.refreshDecisions(); break;
        case 2: backend.refreshProcesses(400); break;
        case 3: backend.refreshNetwork(); break;
        case 4: backend.refreshScans(); break;
        case 5: backend.refreshHardening(); backend.refreshBaseline(); break;
        case 6: backend.refreshCanaries(); break;
        case 7: backend.refreshRemediation(); break;
        case 8: backend.refreshToolbox(); break;
        case 9: backend.refreshMemStatus(); break;                       // Memory
        case 10: backend.refreshSettings(); break;                       // AI analyst (consent state)
        case 11: break;                                                  // Integrations: actions only, no snapshot
        case 12: backend.refreshSnapshots(); break;                      // Backups
        case 13: backend.refreshSnapshots(); backend.refreshRemediation(); break; // Recovery
        case 14: backend.refreshEvents(400); backend.refreshDecisions(); break;   // Timeline
        case 15: backend.refreshSensors(); backend.refreshSettings(); break;      // Settings
        }
    }

    /// Compact thousands: 12.4k rather than 12438, because these are read as
    /// magnitudes in a status bar, not as exact values.
    function formatCount(n) {
        var v = Number(n) || 0;
        if (v < 1000) return String(v);
        if (v < 1000000) return (v / 1000).toFixed(v < 10000 ? 1 : 0) + "k";
        return (v / 1000000).toFixed(1) + "M";
    }

    // ---- shortcuts ----
    Shortcut {
        sequences: [StandardKey.Refresh]
        onActivated: backend.refreshAll()
    }
    Shortcut {
        sequence: "Ctrl+Space"
        onActivated: {
            window.suspended = !window.suspended;
        }
    }
    // Ctrl+1..9 jumps to a page. Registered individually so each shows up correctly
    // in a shortcut inspector and so an out-of-range digit is simply inert.
    Repeater {
        model: window.pages.length
        // Repeater delegates must be Items (a Shortcut is not), so the shortcut
        // lives inside a plain Item holder -- the shortcut is window-scoped
        // regardless of how deep it sits.
        delegate: Item {
            required property int modelData
            width: 0; height: 0
            Shortcut {
                sequence: "Ctrl+" + modelData
                onActivated: window.goTo(modelData - 1)
            }
        }
    }
    Shortcut {
        sequence: "Ctrl+0"
        onActivated: window.goTo(9)
    }
    Shortcut {
        sequences: ["Alt+Right", "Alt+Down"]
        onActivated: window.goTo(window.pageIndex + 1)
    }
    Shortcut {
        sequences: ["Alt+Left", "Alt+Up"]
        onActivated: window.goTo(window.pageIndex - 1)
    }
    // Escape clears the toast stack. It deliberately does NOT close the threat
    // dialog, which sets closePolicy: NoAutoClose for exactly that reason.
    Shortcut {
        sequence: "Escape"
        enabled: threatDialog.visible === false
        onActivated: toasts.clear()
    }

    Component.onCompleted: {
        // One pull at start-up so the first frame is not an empty console, then the
        // timers take over.
        if (backend.connected) backend.refreshAll();
    }
}
