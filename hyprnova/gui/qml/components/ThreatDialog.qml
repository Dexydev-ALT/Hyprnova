// SPDX-License-Identifier: Apache-2.0
// HyprNova :: escalation dialog — the one modal in the console
//
// This is Module 5's escalation pipeline reaching its final step: the agent has
// already FROZEN the process, dumped /proc/<pid>/maps, run YARA over the memory
// strings and batch-scanned the lineage, and it is now handing the decision to a
// human with all of that evidence attached.
//
// Design decisions that follow from that:
//
//   * IT IS MODAL, on purpose. Every other notification in the console is a toast
//     precisely so that this one can be a dialog. A frozen process is a stopped
//     service; leaving it frozen while the operator reads a feed is an outage.
//   * VERDICT FIRST, EVIDENCE SECOND, ACTIONS LAST. The top third answers "how bad
//     and how sure", the middle answers "why do you think so", the bottom is four
//     buttons. Nobody should have to scroll to find "Resume".
//   * THE RECOMMENDATION IS SHOWN BUT NOT PRESELECTED AS THE DEFAULT BUTTON.
//     Preselecting trains operators to hit Enter, and Enter on a quarantine is how
//     a false positive becomes an incident. The recommended action is labelled and
//     outlined; the default focus is the safe one.
//   * FACTORS ARE DISPLAYED WITH THEIR POINTS. "risk 743" is not actionable.
//     "mass file modification +300, canary entropy 7.94 +250, deleted exe +250" is:
//     the operator can see which sensor contributed and decide whether to trust it.
//   * LINEAGE IS A CHAIN, NOT A TABLE. Parentage is the single most predictive thing
//     about a process (nginx -> sh -> curl is an intrusion; nginx -> php-fpm is
//     Tuesday), so it gets a horizontal chain with the suspect highlighted at the
//     end.
//
// The dialog never talks to the agent directly. It emits `answered(id, action)` and
// main.qml routes that to backend.answer(); the agent re-authorises uid==0 inside
// dispatch(), so a compromised console process still cannot act.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../theme"

Dialog {
    id: root

    /// The decision map from backend.decisions / backend.decisionRequired:
    ///   {id, raised, recommendation, answered, report:{...}, factors:[...], actions:[...]}
    property var decision: null

    signal answered(int id, string action)

    readonly property var report: decision ? (decision.report || {}) : ({})
    readonly property var factors: (decision && decision.factors) ? decision.factors : []
    readonly property var actions: (decision && decision.actions) ? decision.actions
                                                                  : ["allow", "suspend", "quarantine", "kill"]
    readonly property string severity: report.severity || "high"
    readonly property color sevColor: Theme.severityColor(severity)
    readonly property int risk: report.risk || 0
    readonly property string recommendation: (decision && decision.recommendation) || ""
    readonly property bool frozen: report.suspended === true && report.resumed !== true

    modal: true
    // No close-on-Escape and no close button: an unanswered escalation must be
    // answered, not dismissed. The agent keeps the process frozen either way, so
    // "closing" the dialog would hide an ongoing outage without resolving it.
    closePolicy: Popup.NoAutoClose
    anchors.centerIn: Overlay.overlay
    width: Math.min(880, parent ? parent.width - Theme.space6 * 2 : 880)
    height: Math.min(720, parent ? parent.height - Theme.space6 * 2 : 720)
    padding: 0
    title: ""

    // Focus lands on Resume — the reversible action. If the operator reflexively
    // hits Enter they unfreeze a service, which is recoverable; the opposite is not.
    onOpened: { if (resumeBtn.visible) resumeBtn.forceActiveFocus(); }

    Overlay.modal: Rectangle {
        // Dimming plus a slow red vignette for critical. The vignette is a gradient
        // rectangle rather than a blur: a layer effect on a full-screen overlay
        // costs an FBO the size of the window on every repaint.
        color: Theme.withAlpha(Theme.voidBlack, 0.78)

        Rectangle {
            anchors.fill: parent
            visible: root.severity === "critical"
            opacity: 0.5
            gradient: Gradient {
                GradientStop { position: 0.0; color: Theme.withAlpha(Theme.critical, 0.22) }
                GradientStop { position: 0.25; color: "transparent" }
                GradientStop { position: 0.75; color: "transparent" }
                GradientStop { position: 1.0; color: Theme.withAlpha(Theme.critical, 0.22) }
            }
            SequentialAnimation on opacity {
                running: root.visible && root.severity === "critical"
                loops: Animation.Infinite
                NumberAnimation { to: 0.2; duration: Theme.pulseMs; easing.type: Easing.InOutSine }
                NumberAnimation { to: 0.5; duration: Theme.pulseMs; easing.type: Easing.InOutSine }
            }
        }
    }

    background: Rectangle {
        radius: Theme.radiusLg
        color: Theme.surface
        border.width: 1
        border.color: Theme.withAlpha(root.sevColor, 0.55)

        // Top spine in the severity colour: the first thing visible even before the
        // text is read.
        Rectangle {
            anchors { left: parent.left; right: parent.right; top: parent.top }
            height: 3
            radius: Theme.radiusLg
            color: root.sevColor
        }
    }

    contentItem: ColumnLayout {
        spacing: 0

        // ============ 1. VERDICT ==========================================
        Item {
            Layout.fillWidth: true
            Layout.preferredHeight: 96

            Rectangle {
                anchors.fill: parent
                color: Theme.withAlpha(root.sevColor, 0.07)
            }

            RowLayout {
                anchors { fill: parent; margins: Theme.space5 }
                spacing: Theme.space4

                GlowDot {
                    size: 16
                    color: root.sevColor
                    glow: true
                    // Pulsing while the process is frozen: the animation is the
                    // "this is still waiting on you" reminder.
                    pulse: root.frozen
                    Layout.alignment: Qt.AlignVCenter
                }

                ColumnLayout {
                    spacing: 2
                    Layout.fillWidth: true
                    Layout.alignment: Qt.AlignVCenter

                    RowLayout {
                        spacing: Theme.space3
                        Label {
                            text: qsTr("Escalation requires your decision")
                            color: Theme.text
                            font {
                                pixelSize: Theme.fontSizeTitle
                                family: Theme.fontFamily
                                weight: Theme.weightBold
                                letterSpacing: 0.1
                            }
                        }
                        SevBadge {
                            text: root.severity
                            solid: true
                            Layout.alignment: Qt.AlignVCenter
                        }
                        SevBadge {
                            visible: root.frozen
                            text: qsTr("process frozen")
                            customColor: Theme.high
                            pulse: true
                            Layout.alignment: Qt.AlignVCenter
                        }
                    }

                    Label {
                        text: {
                            var exe = String(root.report.exe || "");
                            var comm = exe.length > 0 ? Theme.baseName(exe) : qsTr("unknown binary");
                            var pid = root.report.pid !== undefined ? root.report.pid : "?";
                            var step = String(root.report.step || "");
                            return comm + " (pid " + pid + ")"
                                   + (step.length > 0 ? "  \u2014  pipeline reached: " + step : "");
                        }
                        color: Theme.textDim
                        font.pixelSize: Theme.fontSizeBody
                        font.family: Theme.monoFamily
                        elide: Text.ElideMiddle
                        Layout.fillWidth: true
                    }

                    Label {
                        // How long it has been frozen. A stopped service is measured
                        // in minutes, so this counts up in real time rather than
                        // showing a static "raised at".
                        text: root.frozen
                              ? qsTr("Frozen for %1 \u2014 every second of this is downtime.")
                                    .arg(Theme.formatUptime(Math.max(0, nowTick.epoch - (root.decision.raised || nowTick.epoch))))
                              : qsTr("Raised %1").arg(Theme.formatDate(root.decision.raised || 0))
                        color: root.frozen ? Theme.high : Theme.textFaint
                        font.pixelSize: Theme.fontSizeSmall
                        font.family: Theme.fontFamily
                        Layout.fillWidth: true
                    }
                }

                // Risk dial. Big number, banded colour, and the threshold that the
                // agent's auto-responder would have acted at — so the operator can
                // see whether they are overriding the machine or agreeing with it.
                ColumnLayout {
                    spacing: 0
                    Layout.alignment: Qt.AlignVCenter
                    Layout.rightMargin: Theme.space2

                    Label {
                        text: Math.round(root.risk)
                        color: Theme.riskColor(root.risk)
                        Layout.alignment: Qt.AlignHCenter
                        font {
                            pixelSize: Theme.fontSizeHero
                            family: Theme.monoFamily
                            weight: Theme.weightBold
                        }
                    }
                    Label {
                        text: qsTr("RISK / 1000")
                        color: Theme.textFaint
                        Layout.alignment: Qt.AlignHCenter
                        font {
                            pixelSize: Theme.fontSizeMicro
                            family: Theme.fontFamily
                            weight: Theme.weightBold
                            letterSpacing: 1.2
                        }
                    }
                    RiskBar {
                        risk: root.risk
                        showValue: false
                        Layout.preferredWidth: 120
                        Layout.preferredHeight: 8
                        Layout.alignment: Qt.AlignHCenter
                        Layout.topMargin: Theme.space2
                    }
                }
            }
        }

        Rectangle { Layout.fillWidth: true; height: 1; color: Theme.border }

        // ============ 2. EVIDENCE =========================================
        Flickable {
            Layout.fillWidth: true
            Layout.fillHeight: true
            contentWidth: width
            contentHeight: evidence.height + Theme.space5 * 2
            clip: true
            boundsBehavior: Flickable.StopAtBounds
            ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

            ColumnLayout {
                id: evidence
                width: parent.width
                spacing: Theme.space4

                Item { Layout.preferredHeight: Theme.space1 }

                // ---- lineage chain ----
                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.leftMargin: Theme.space5
                    Layout.rightMargin: Theme.space5
                    spacing: Theme.space2

                    SectionTitle { text: qsTr("Process lineage") }

                    Label {
                        // The chain is a single wrapped line rather than a tree: the
                        // question here is "what led to this", which is linear.
                        text: {
                            var l = root.report.lineage;
                            if (!l || l.length === 0) return qsTr("lineage unavailable (process exited before /proc could be read)");
                            var parts = [];
                            for (var i = 0; i < l.length; ++i) parts.push(String(l[i]));
                            return parts.join("  \u2192  ");
                        }
                        color: Theme.text
                        font.pixelSize: Theme.fontSizeBody
                        font.family: Theme.monoFamily
                        wrapMode: Text.WrapAnywhere
                        Layout.fillWidth: true
                        // Colour the final hop, which is the suspect, by rendering
                        // the whole chain dim and overlaying nothing: simpler and
                        // cheaper than a Repeater of Labels for a value read once.
                        opacity: 0.92
                    }

                    Label {
                        text: qsTr("Read right-to-left: the rightmost entry is the frozen process.")
                        color: Theme.textFaint
                        font.pixelSize: Theme.fontSizeSmall
                        Layout.fillWidth: true
                    }
                }

                // ---- risk factors ----
                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.leftMargin: Theme.space5
                    Layout.rightMargin: Theme.space5
                    spacing: Theme.space2
                    visible: root.factors.length > 0

                    SectionTitle {
                        text: qsTr("Why the score is %1").arg(Math.round(root.risk))
                    }

                    Repeater {
                        model: root.factors

                        delegate: Rectangle {
                            id: factor

                            required property var modelData
                            readonly property int points: modelData.points || 0
                            readonly property color ptColor: points >= 250 ? Theme.critical
                                                             : points >= 120 ? Theme.high
                                                             : points >= 40  ? Theme.medium
                                                                             : Theme.info

                            Layout.fillWidth: true
                            Layout.preferredHeight: fRow.height + Theme.space3
                            radius: Theme.radiusSm
                            color: Theme.surfaceAlt
                            border.width: 1
                            border.color: Theme.borderSoft

                            RowLayout {
                                id: fRow
                                anchors {
                                    left: parent.left; right: parent.right
                                    verticalCenter: parent.verticalCenter
                                    leftMargin: Theme.space3; rightMargin: Theme.space3
                                }
                                spacing: Theme.space3

                                // Signed points, right-aligned in a fixed column so
                                // the eye can sum them vertically.
                                Label {
                                    text: (factor.points >= 0 ? "+" : "") + factor.points
                                    color: factor.ptColor
                                    Layout.preferredWidth: 52
                                    horizontalAlignment: Text.AlignRight
                                    font {
                                        pixelSize: Theme.fontSizeBody
                                        family: Theme.monoFamily
                                        weight: Theme.weightBold
                                    }
                                }

                                Rectangle {
                                    Layout.preferredWidth: 3
                                    Layout.preferredHeight: 22
                                    radius: 1
                                    color: factor.ptColor
                                }

                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 0

                                    RowLayout {
                                        spacing: Theme.space2
                                        Label {
                                            text: factor.modelData.trigger || ""
                                            color: Theme.text
                                            font {
                                                pixelSize: Theme.fontSizeBody
                                                family: Theme.fontFamily
                                                weight: Theme.weightMedium
                                            }
                                            Layout.fillWidth: true
                                            elide: Text.ElideRight
                                        }
                                        SevBadge {
                                            text: factor.modelData.sensor || ""
                                            autoColor: false
                                            customColor: Theme.textFaint
                                        }
                                    }
                                    Label {
                                        text: factor.modelData.evidence || ""
                                        visible: (factor.modelData.evidence || "").length > 0
                                        color: Theme.textDim
                                        font.pixelSize: Theme.fontSizeSmall
                                        font.family: Theme.monoFamily
                                        Layout.fillWidth: true
                                        wrapMode: Text.WrapAnywhere
                                        maximumLineCount: 3
                                        elide: Text.ElideRight
                                    }
                                }
                            }
                        }
                    }
                }

                // ---- memory forensics ----
                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.leftMargin: Theme.space5
                    Layout.rightMargin: Theme.space5
                    spacing: Theme.space2

                    SectionTitle {
                        text: qsTr("Memory inspection")
                        detail: qsTr("%1 regions scanned \u00B7 %2 writable+executable")
                                    .arg(root.report.regions_scanned || 0)
                                    .arg(root.report.wx_regions || 0)
                    }

                    // W^X violations are the strongest single indicator in the whole
                    // report: a region that is both writable and executable exists
                    // almost only because something wrote code into it at runtime.
                    Rectangle {
                        Layout.fillWidth: true
                        Layout.preferredHeight: wxRow.height + Theme.space3
                        visible: (root.report.wx_regions || 0) > 0
                        radius: Theme.radiusSm
                        color: Theme.withAlpha(Theme.critical, 0.10)
                        border.width: 1
                        border.color: Theme.withAlpha(Theme.critical, 0.45)

                        RowLayout {
                            id: wxRow
                            anchors {
                                left: parent.left; right: parent.right
                                verticalCenter: parent.verticalCenter
                                leftMargin: Theme.space3; rightMargin: Theme.space3
                            }
                            spacing: Theme.space3
                            GlowDot { size: 9; color: Theme.critical; glow: true; pulse: true }
                            Label {
                                text: qsTr("%1 region(s) mapped writable AND executable \u2014 a W^X violation. " +
                                           "Legitimate code does not need this; injected code always does.")
                                          .arg(root.report.wx_regions || 0)
                                color: Theme.text
                                font.pixelSize: Theme.fontSizeSmall
                                Layout.fillWidth: true
                                wrapMode: Text.WordWrap
                            }
                        }
                    }

                    // YARA hits over memory strings. Shown verbatim, including the
                    // rule name, because a false positive is only diagnosable if the
                    // operator can see WHICH rule fired.
                    Repeater {
                        model: (root.report.memory_matches || [])

                        delegate: Rectangle {
                            required property var modelData
                            Layout.fillWidth: true
                            Layout.preferredHeight: mmRow.height + Theme.space3
                            radius: Theme.radiusSm
                            color: Theme.surfaceAlt
                            border.width: 1
                            border.color: Theme.withAlpha(Theme.high, 0.35)

                            RowLayout {
                                id: mmRow
                                anchors {
                                    left: parent.left; right: parent.right
                                    verticalCenter: parent.verticalCenter
                                    leftMargin: Theme.space3; rightMargin: Theme.space3
                                }
                                spacing: Theme.space3
                                Label {
                                    text: "\u25B6"
                                    color: Theme.high
                                    font.pixelSize: Theme.fontSizeSmall
                                }
                                Label {
                                    // modelData is either a bare rule name (string) or
                                    // {rule, address, ...}; handle both so a bridge
                                    // change cannot blank the evidence panel.
                                    text: typeof modelData === "string" ? modelData
                                          : (modelData.rule || modelData.name || JSON.stringify(modelData))
                                    color: Theme.text
                                    font.pixelSize: Theme.fontSizeBody
                                    font.family: Theme.monoFamily
                                    Layout.fillWidth: true
                                    elide: Text.ElideRight
                                }
                                SevBadge { text: qsTr("in memory"); autoColor: false; customColor: Theme.high }
                            }
                        }
                    }

                    Label {
                        visible: (root.report.memory_matches || []).length === 0
                        text: qsTr("No YARA rule matched the process memory strings.")
                        color: Theme.textFaint
                        font.pixelSize: Theme.fontSizeSmall
                        Layout.fillWidth: true
                    }
                }

                // ---- lineage scan results ----
                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.leftMargin: Theme.space5
                    Layout.rightMargin: Theme.space5
                    Layout.bottomMargin: Theme.space4
                    spacing: Theme.space2
                    visible: ((root.report.scanned_paths || []).length > 0)
                             || ((root.report.findings || []).length > 0)

                    SectionTitle {
                        text: qsTr("Lineage scan")
                        detail: qsTr("%1 binaries \u00B7 %2 findings")
                                    .arg((root.report.scanned_paths || []).length)
                                    .arg((root.report.findings || []).length)
                    }

                    Repeater {
                        model: (root.report.findings || [])

                        delegate: RowLayout {
                            required property var modelData
                            Layout.fillWidth: true
                            spacing: Theme.space2

                            SevBadge {
                                text: (typeof modelData === "object" && modelData.severity)
                                      ? modelData.severity : "info"
                            }
                            Label {
                                text: typeof modelData === "string" ? modelData
                                      : ((modelData.rule || "") + "  " + (modelData.path || modelData.exe || ""))
                                color: Theme.textDim
                                font.pixelSize: Theme.fontSizeSmall
                                font.family: Theme.monoFamily
                                Layout.fillWidth: true
                                elide: Text.ElideMiddle
                            }
                        }
                    }

                    // The scanned binaries, collapsed into one wrapped line. Listing
                    // them matters even when all are clean: it shows the operator
                    // the sweep actually covered the parent chain rather than only
                    // the suspect.
                    Label {
                        text: qsTr("Scanned: ") + (root.report.scanned_paths || []).join(", ")
                        color: Theme.textFaint
                        font.pixelSize: Theme.fontSizeSmall
                        font.family: Theme.monoFamily
                        wrapMode: Text.WrapAnywhere
                        Layout.fillWidth: true
                        visible: (root.report.scanned_paths || []).length > 0
                    }
                }
            }
        }

        Rectangle { Layout.fillWidth: true; height: 1; color: Theme.border }

        // ============ 3. ACTIONS ==========================================
        Item {
            Layout.fillWidth: true
            Layout.preferredHeight: actionCol.height + Theme.space4 * 2

            Rectangle { anchors.fill: parent; color: Theme.surfaceAlt; radius: 0 }

            ColumnLayout {
                id: actionCol
                anchors {
                    left: parent.left; right: parent.right
                    verticalCenter: parent.verticalCenter
                    leftMargin: Theme.space5; rightMargin: Theme.space5
                }
                spacing: Theme.space3

                Label {
                    visible: root.recommendation.length > 0
                    text: qsTr("Agent recommends: %1. It will not act on your behalf while auto-respond is off.")
                              .arg(root.recommendation.toUpperCase())
                    color: Theme.textDim
                    font.pixelSize: Theme.fontSizeSmall
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.space2

                    NovaButton {
                        id: resumeBtn
                        text: qsTr("Resume (SIGCONT)")
                        role: "primary"
                        visible: root.hasAction("allow") || root.hasAction("resume")
                        Layout.preferredWidth: 168
                        onTriggered: {
                            root.answered(root.decision.id, "allow");
                            root.close();
                        }
                        ToolTip.visible: hovered
                        ToolTip.text: qsTr("Unfreeze and let it run. Reversible; the agent keeps watching it.")
                    }

                    NovaButton {
                        text: qsTr("Keep frozen")
                        role: "secondary"
                        visible: root.hasAction("suspend")
                        Layout.fillWidth: true
                        onTriggered: {
                            root.answered(root.decision.id, "suspend");
                            root.close();
                        }
                        ToolTip.visible: hovered
                        ToolTip.text: qsTr("Leave it SIGSTOP'd while you investigate by hand. It stays down.")
                    }

                    NovaButton {
                        text: qsTr("Quarantine")
                        role: "danger"
                        confirm: true
                        visible: root.hasAction("quarantine")
                        Layout.fillWidth: true
                        onTriggered: {
                            root.answered(root.decision.id, "quarantine");
                            root.close();
                        }
                        ToolTip.visible: hovered
                        ToolTip.text: qsTr("Hash and move the executable to quarantine (0400), then stop it. " +
                                           "Restorable from the Remediation page.")
                    }

                    NovaButton {
                        text: qsTr("Kill")
                        role: "danger"
                        confirm: true
                        visible: root.hasAction("kill")
                        Layout.preferredWidth: 96
                        onTriggered: {
                            root.answered(root.decision.id, "kill");
                            root.close();
                        }
                        ToolTip.visible: hovered
                        ToolTip.text: qsTr("SIGKILL. The executable is preserved as a 0400 sample before the kill, " +
                                           "so evidence is not lost.")
                    }
                }

                Label {
                    text: qsTr("Every choice is written to the action journal with your uid and is undoable from the Remediation page.")
                    color: Theme.textFaint
                    font.pixelSize: Theme.fontSizeMicro
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                }
            }
        }
    }

    function hasAction(a) { return actions.indexOf(a) >= 0; }

    // One-second tick, only while the dialog is open, to drive the frozen-for timer.
    Timer {
        id: nowTick
        property int epoch: Math.floor(Date.now() / 1000)
        interval: 1000
        repeat: true
        running: root.visible
        onTriggered: epoch = Math.floor(Date.now() / 1000)
    }
}
