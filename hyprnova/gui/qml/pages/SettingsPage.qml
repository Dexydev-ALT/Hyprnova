// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Settings
//
// The console's own page, plus the agent's runtime state that is not a "sensor":
// sensor inventory with per-sensor detail, capability gaps, the learning baseline,
// and the operational controls (reload config, run self-test, view the socket path).
//
// Nothing here changes detection behaviour except Reload, and Reload is a config
// reload — not a restart. That is stated on the button, because "reload" and
// "restart" are different words with different consequences and an operator who
// conflates them will be surprised.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import "../theme"
import "../components"

Item {
    id: page

    readonly property var baseline: backend.baseline
    readonly property var sensors: backend.sensors
    readonly property var caps: backend.capabilities
    readonly property var notes: backend.capabilityNotes

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

            // ================= OPERATIONS =================================
            Panel {
                Layout.fillWidth: true
                title: qsTr("Operations")
                subtitle: qsTr("agent-level controls \u2014 these go to the agent, not to this console")
                glyph: "\u2699"
                GridLayout {
                    Layout.fillWidth: true
                    columns: parent.width >= 900 ? 4 : 2
                    columnSpacing: Theme.space4
                    rowSpacing: Theme.space3

                    NovaButton {
                        Layout.fillWidth: true
                        text: qsTr("Reload configuration")
                        role: "primary"
                        onTriggered: backend.reloadConfig()
                        ToolTip.visible: hovered
                        ToolTip.text: qsTr("SIGHUP to the agent. Sensors pause for the swap; " +
                                           "coverage resumes in a few seconds. Not a restart.")
                    }
                    NovaButton {
                        Layout.fillWidth: true
                        text: qsTr("Run self-test")
                        role: "secondary"
                        onTriggered: backend.runSelfTest()
                        ToolTip.visible: hovered
                        ToolTip.text: qsTr("58 checks: FIPS 180-4 SHA-256, RFC 4231 HMAC, entropy, " +
                                           "both lock-free rings, the event bus, /proc enrichment, " +
                                           "the subprocess layer, JSON, atomic writes, the rule engine.")
                    }
                    NovaButton {
                        Layout.fillWidth: true
                        text: qsTr("Re-plant canaries")
                        role: "secondary"
                        onTriggered: backend.plantCanaries()
                    }
                    NovaButton {
                        Layout.fillWidth: true
                        text: qsTr("Full scan sweep")
                        role: "secondary"
                        onTriggered: backend.fullSweep()
                    }
                }

                Rectangle { Layout.fillWidth: true; height: 1; color: Theme.border; Layout.topMargin: Theme.space2 }

                GridLayout {
                    Layout.fillWidth: true
                    columns: 2
                    columnSpacing: Theme.space4
                    rowSpacing: Theme.space1

                    Repeater {
                        model: [
                            { k: qsTr("Agent socket"),   v: agentSocket },
                            { k: qsTr("Console version"),v: "v" + guiVersion },
                            { k: qsTr("Agent version"),  v: backend.version || qsTr("unknown") },
                            { k: qsTr("Agent uptime"),   v: Theme.formatUptime(backend.uptime) },
                            { k: qsTr("Refresh rate"),   v: refreshHz + " Hz" },
                            { k: qsTr("Theme"),          v: themeName },
                            { k: qsTr("GUI clients"),    v: String(backend.guiClients) },
                            { k: qsTr("Bus frames"),     v: String(backend.guiFrames) }
                        ]
                        delegate: RowLayout {
                            required property var modelData
                            Layout.fillWidth: true
                            spacing: Theme.space2
                            Label {
                                text: modelData.k
                                color: Theme.textFaint
                                font.pixelSize: Theme.fontSizeSmall
                                Layout.preferredWidth: 130
                            }
                            Label {
                                text: modelData.v
                                color: Theme.textDim
                                font.pixelSize: Theme.fontSizeSmall
                                font.family: Theme.monoFamily
                                elide: Text.ElideMiddle
                                Layout.fillWidth: true
                            }
                        }
                    }
                }
            }

            // ================= PROTECTION SWITCHES ========================
            // Every agent feature is a plain ON/OFF. No config editing, no
            // switches inside switches: the daemon validates, applies, persists
            // and hot-reloads, and refuses a toggle that would make the config
            // invalid. A refused toggle snaps back -- the switch is never left
            // lying about the agent's real state.
            Panel {
                Layout.fillWidth: true
                title: qsTr("Protection switches")
                subtitle: qsTr("%1 features \u00B7 ON applies immediately and survives a restart").arg(backend.featureSettings.length)
                glyph: "\u26A1"
                headerRight: NovaButton {
                    text: qsTr("Refresh")
                    role: "ghost"
                    compact: true
                    glyph: "\u21BB"
                    onTriggered: backend.refreshSettings()
                }

                ColumnLayout {
                    width: parent.width
                    spacing: 0

                    Repeater {
                        model: backend.featureSettings

                        delegate: Rectangle {
                            id: tRow
                            required property var modelData
                            readonly property bool on: modelData.on === true

                            Layout.fillWidth: true
                            height: 42
                            radius: Theme.radiusSm
                            color: tHover.containsMouse ? Theme.surfaceAlt : "transparent"

                            RowLayout {
                                anchors { fill: parent; leftMargin: Theme.space2; rightMargin: Theme.space3 }
                                spacing: Theme.space3

                                // track + knob
                                Rectangle {
                                    id: track
                                    Layout.preferredWidth: 40
                                    Layout.preferredHeight: 20
                                    radius: 10
                                    color: tRow.on ? Theme.withAlpha(Theme.good, 0.55)
                                                   : Theme.withAlpha(Theme.textFaint, 0.25)
                                    border.width: 1
                                    border.color: tRow.on ? Theme.good : Theme.border
                                    Behavior on color { ColorAnimation { duration: 140 } }

                                    Rectangle {
                                        x: tRow.on ? parent.width - width - 2 : 2
                                        anchors.verticalCenter: parent.verticalCenter
                                        width: 16; height: 16; radius: 8
                                        color: tRow.on ? Theme.good : Theme.textFaint
                                        Behavior on x { NumberAnimation { duration: 120; easing.type: Easing.OutQuad } }
                                    }
                                }

                                Label {
                                    text: tRow.modelData.key || "?"
                                    color: Theme.text
                                    font.pixelSize: Theme.fontSizeSmall
                                    font.family: Theme.monoFamily
                                    Layout.preferredWidth: 168
                                    elide: Text.ElideRight
                                }
                                Label {
                                    text: tRow.modelData.description || ""
                                    color: Theme.textFaint
                                    font.pixelSize: Theme.fontSizeSmall
                                    elide: Text.ElideRight
                                    Layout.fillWidth: true
                                }
                                Label {
                                    text: tRow.on ? "ON" : "OFF"
                                    color: tRow.on ? Theme.good : Theme.textFaint
                                    font.pixelSize: Theme.fontSizeMicro
                                    font.family: Theme.monoFamily
                                    Layout.preferredWidth: 34
                                }
                            }

                            HoverHandler { id: tHover }
                            TapHandler {
                                onTapped: backend.setFeature(tRow.modelData.key || "", !tRow.on)
                            }
                            ToolTip.visible: tHover.containsMouse && (tRow.modelData.key || "") === "dry_run"
                            ToolTip.text: qsTr("observe-only: detections still fire, responses never do")
                        }
                    }

                    EmptyState {
                        visible: backend.featureSettings.length === 0
                        good: !backend.connected
                        message: backend.connected ? qsTr("Reading the feature table...")
                                                   : qsTr("Not connected to the agent")
                        hint: backend.connected ? "" : qsTr("Switches appear once the console links up.")
                        Layout.fillWidth: true
                    }
                }
            }

            // ================= SENSORS ====================================
            Panel {
                Layout.fillWidth: true
                Layout.preferredHeight: sensorList.height + 76
                title: qsTr("Sensors")
                subtitle: qsTr("%1 reporting \u00B7 degraded sensors have partial coverage").arg(page.sensors.length)
                glyph: "\u25A0"
                headerRight: NovaButton {
                    text: qsTr("Refresh")
                    role: "ghost"
                    compact: true
                    glyph: "\u21BB"
                    onTriggered: backend.refreshSensors()
                }

                ListView {
                    id: sensorList
                    anchors { left: parent.left; right: parent.right; bottom: parent.bottom }
                    height: Math.min(contentHeight, 360)
                    model: page.sensors
                    spacing: 2
                    clip: true
                    boundsBehavior: Flickable.StopAtBounds
                    reuseItems: true

                    delegate: Rectangle {
                        id: sRow
                        required property var modelData
                        readonly property string st: String(modelData.state || "unknown").toLowerCase()
                        readonly property bool degraded: sRow.st === "degraded" || sRow.st === "failed"

                        width: ListView.view.width
                        height: 46
                        radius: Theme.radiusSm
                        color: sHover.containsMouse ? Theme.surfaceAlt
                             : sRow.degraded ? Theme.withAlpha(Theme.medium, 0.06) : "transparent"

                        RowLayout {
                            anchors { fill: parent; leftMargin: Theme.space3; rightMargin: Theme.space3 }
                            spacing: Theme.space3

                            GlowDot {
                                size: 10
                                color: Theme.sensorStateColor(sRow.st)
                                glow: sRow.st === "running" || sRow.st === "failed"
                                pulse: sRow.st === "failed"
                            }
                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: 0
                                Label {
                                    text: sRow.modelData.name || "?"
                                    color: Theme.text
                                    font { pixelSize: Theme.fontSizeBody; family: Theme.fontFamily; weight: Theme.weightMedium }
                                }
                                Label {
                                    text: sRow.modelData.detail || sRow.st
                                    color: Theme.textFaint
                                    font.pixelSize: Theme.fontSizeMicro
                                    font.family: Theme.monoFamily
                                    elide: Text.ElideRight
                                    Layout.fillWidth: true
                                }
                            }
                            ColumnLayout {
                                Layout.alignment: Qt.AlignVCenter
                                spacing: 0
                                Label {
                                    text: page.fmt(sRow.modelData.emitted || 0) + qsTr(" emitted")
                                    color: Theme.textDim
                                    font.pixelSize: Theme.fontSizeSmall
                                    font.family: Theme.monoFamily
                                    Layout.alignment: Qt.AlignRight
                                }
                                Label {
                                    text: (sRow.modelData.dropped || 0) > 0
                                          ? qsTr("%1 dropped \u00B7 %2 errors \u00B7 %3 restarts")
                                                .arg(sRow.modelData.dropped).arg(sRow.modelData.errors || 0)
                                                .arg(sRow.modelData.restarts || 0)
                                          : qsTr("cpu %1% \u00B7 rss %2")
                                                .arg(Math.round((sRow.modelData.cpu || 0) * 10) / 10)
                                                .arg(Theme.formatBytes(sRow.modelData.rss || 0))
                                    color: (sRow.modelData.dropped || 0) > 0 ? Theme.high : Theme.textFaint
                                    font.pixelSize: Theme.fontSizeMicro
                                    font.family: Theme.monoFamily
                                    Layout.alignment: Qt.AlignRight
                                }
                            }
                        }

                        HoverHandler { id: sHover }
                        ToolTip.visible: sHover.containsMouse
                        ToolTip.text: {
                            var m = sRow.modelData;
                            var parts = [qsTr("state %1").arg(m.state || "?"),
                                         qsTr("emitted %1 \u00B7 dropped %2 \u00B7 delivered %3 \u00B7 slow %4")
                                             .arg(m.emitted || 0).arg(m.dropped || 0)
                                             .arg(m.delivered || 0).arg(m.slow || 0),
                                         qsTr("errors %1 \u00B7 restarts %2").arg(m.errors || 0).arg(m.restarts || 0),
                                         qsTr("started %1 \u00B7 last activity %2")
                                             .arg(m.started_at ? Theme.formatDate(m.started_at) : "?")
                                             .arg(m.last_activity ? Theme.formatDate(m.last_activity) : "?")];
                            if (m.caps_missing && m.caps_missing.length > 0)
                                parts.push(qsTr("missing capabilities: %1").arg(m.caps_missing.join(", ")));
                            if (m.deps_missing && m.deps_missing.length > 0)
                                parts.push(qsTr("missing dependencies: %1").arg(m.deps_missing.join(", ")));
                            return parts.join("\n");
                        }
                        ToolTip.wrapMode: Text.WrapAnywhere
                    }
                }
            }

            // ================= CAPABILITIES =================================
            Panel {
                Layout.fillWidth: true
                Layout.preferredHeight: capGrid.height + 76
                title: qsTr("Capabilities")
                subtitle: qsTr("what this install of the agent can do \u2014 and what it cannot")
                glyph: "\u26A0"
                accentColor: Theme.medium

                GridLayout {
                    id: capGrid
                    Layout.fillWidth: true
                    columns: parent.width >= 900 ? 3 : 2
                    columnSpacing: Theme.space4
                    rowSpacing: Theme.space2

                    Repeater {
                        model: [
                            { k: "signal",    label: qsTr("Signal processes"),  help: qsTr("SIGSTOP/SIGCONT/SIGKILL to any pid") },
                            { k: "cgroup",    label: qsTr("cgroup isolation"),  help: qsTr("pids.max, cpu.max, memory.max, freeze") },
                            { k: "network",   label: qsTr("Block C2 (nft)"),    help: qsTr("nftables ruleset managed by the agent") },
                            { k: "quarantine",label: qsTr("Quarantine files"),  help: qsTr("hash, move to 0400, unlink original") },
                            { k: "notify",    label: qsTr("Desktop notify"),    help: qsTr("notify-send as the logged-in user") },
                            { k: "signal",    label: qsTr("Run as root"),       help: qsTr("euid 0 \u2014 required for most of the above"), dup: true }
                        ]
                        delegate: RowLayout {
                            required property var modelData
                            visible: !modelData.dup || backend.capabilities.euid === 0
                            Layout.fillWidth: true
                            spacing: Theme.space2

                            GlowDot {
                                size: 9
                                color: page.caps[modelData.k] === true ? Theme.ok
                                     : page.caps[modelData.k] === false ? Theme.down : Theme.textFaint
                                glow: page.caps[modelData.k] === true
                            }
                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: 0
                                Label {
                                    text: modelData.label
                                    color: Theme.text
                                    font.pixelSize: Theme.fontSizeSmall
                                    font.family: Theme.fontFamily
                                }
                                Label {
                                    text: modelData.help
                                    color: Theme.textFaint
                                    font.pixelSize: Theme.fontSizeMicro
                                    font.family: Theme.monoFamily
                                    elide: Text.ElideRight
                                    Layout.fillWidth: true
                                }
                            }
                            Label {
                                text: page.caps[modelData.k] === true ? qsTr("yes")
                                     : page.caps[modelData.k] === false ? qsTr("no") : qsTr("?")
                                color: page.caps[modelData.k] === true ? Theme.ok
                                     : page.caps[modelData.k] === false ? Theme.down : Theme.textFaint
                                font.pixelSize: Theme.fontSizeSmall
                                font.family: Theme.monoFamily
                            }
                        }
                    }
                }

                // Free-form notes from the agent: these carry the "why" that a boolean
                // cannot ("fanotify permission events need CAP_DAC_READ_SEARCH, which
                // this euid does not have").
                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.space3
                    spacing: Theme.space1
                    visible: page.notes.length > 0
                    Repeater {
                        model: page.notes
                        delegate: RowLayout {
                            required property var modelData
                            Layout.fillWidth: true
                            spacing: Theme.space2
                            Label { text: "\u2022"; color: Theme.medium; font.pixelSize: Theme.fontSizeSmall }
                            Label {
                                text: String(modelData)
                                color: Theme.textDim
                                font.pixelSize: Theme.fontSizeSmall
                                font.family: Theme.monoFamily
                                wrapMode: Text.WordWrap
                                Layout.fillWidth: true
                            }
                        }
                    }
                }
            }

            // ================= BASELINE ===================================
            Panel {
                Layout.fillWidth: true
                Layout.preferredHeight: baselineCol.height + 76
                title: qsTr("Behavioural baseline")
                subtitle: backend.learning ? qsTr("learning \u2014 %1% through the window")
                                              .arg(Math.round(backend.learningProgress * 100))
                                          : qsTr("established")
                glyph: "\u25CE"
                accentColor: backend.learning ? Theme.medium : Theme.ok

                ColumnLayout {
                    id: baselineCol
                    Layout.fillWidth: true
                    spacing: Theme.space3

                    ProgressBar {
                        visible: backend.learning
                        Layout.fillWidth: true
                        Layout.preferredHeight: 6
                        from: 0; to: 1
                        value: backend.learningProgress
                        palette.highlight: Theme.medium
                        palette.dark: Theme.surfaceAlt
                    }

                    GridLayout {
                        Layout.fillWidth: true
                        columns: 4
                        columnSpacing: Theme.space4
                        rowSpacing: Theme.space2

                        Repeater {
                            model: [
                                { k: qsTr("Observations"),   v: page.fmt(page.baseline.observations) },
                                { k: qsTr("Distinct exes"),  v: page.fmt(page.baseline.distinct_exes) },
                                { k: qsTr("Distinct lineages"), v: page.fmt(page.baseline.distinct_lineages) },
                                { k: qsTr("Distinct uids"),  v: page.fmt(page.baseline.distinct_uids) }
                            ]
                            delegate: ColumnLayout {
                                required property var modelData
                                spacing: 0
                                Label {
                                    text: modelData.k
                                    color: Theme.textFaint
                                    font { pixelSize: Theme.fontSizeMicro; family: Theme.fontFamily; weight: Theme.weightBold; letterSpacing: 1.0 }
                                }
                                Label {
                                    text: modelData.v
                                    color: Theme.text
                                    font { pixelSize: Theme.fontSizeTitle; family: Theme.monoFamily; weight: Theme.weightBold }
                                }
                            }
                        }
                    }

                    Label {
                        text: qsTr("Window: %1 hours \u00B7 started %2 \u00B7 ends %3")
                              .arg(page.baseline.learning_window_hours || 0)
                              .arg(page.baseline.started ? Theme.formatDate(page.baseline.started) : "?")
                              .arg(page.baseline.ends ? Theme.formatDate(page.baseline.ends) : "?")
                        color: Theme.textDim
                        font.pixelSize: Theme.fontSizeSmall
                        font.family: Theme.monoFamily
                        Layout.fillWidth: true
                        elide: Text.ElideRight
                    }
                }
            }

            // ================= ABOUT ======================================
            Panel {
                Layout.fillWidth: true
                title: qsTr("About")
                glyph: "\u25A6"
                showAccent: false

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: Theme.space2

                    Label {
                        text: qsTr("HyprNova Anti-Malware Sec \u2014 a Linux anti-malware and " +
                                   "endpoint-response agent with a Qt6 console. The console is a " +
                                   "separate, unprivileged process: it connects over an AF_UNIX " +
                                   "socket and the agent re-authorises every mutating command " +
                                   "against the peer uid.")
                        color: Theme.textDim
                        font.pixelSize: Theme.fontSizeSmall
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }
                    Label {
                        text: qsTr("Modules: boot trust \u00B7 canaries \u00B7 static scanning \u00B7 behavioural " +
                                   "sensors (Falco/auditd/osquery/Suricata) \u00B7 heuristic escalation \u00B7 " +
                                   "active remediation \u00B7 this console.")
                        color: Theme.textFaint
                        font.pixelSize: Theme.fontSizeSmall
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }
                    Label {
                        text: qsTr("Keyboard: Ctrl+1..9 switch pages \u00B7 Ctrl+R refresh \u00B7 Ctrl+Space pause " +
                                   "the feed \u00B7 Alt+arrows navigate \u00B7 Esc clears toasts.")
                        color: Theme.textFaint
                        font.pixelSize: Theme.fontSizeSmall
                        font.family: Theme.monoFamily
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }
                }
            }
        }
    }

    function fmt(n) {
        var v = Number(n) || 0;
        if (v < 10000) return String(v);
        if (v < 1000000) return (v / 1000).toFixed(1) + "k";
        return (v / 1000000).toFixed(2) + "M";
    }
}
