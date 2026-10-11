// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Hardening
//
// Module 1's console. The page is organised as a SCORE at the top and three
// sections underneath, because hardening findings are only actionable when they
// are grouped by what the operator can do about them:
//
//   BOOT TRUST   — Secure Boot, MOK, kernel lockdown, module signatures, taint
//                  flags, initramfs, bootloader integrity. Mostly read-only:
//                  you cannot fix a missing Secure Boot from a console.
//   KERNEL       — the sysctl posture: ASLR, ptrace_scope, kptr_restrict, etc.
//                  Every one of these IS fixable from here, and `harden` writes
//                  /proc/sys directly and verifies the read-back.
//   MAC          — AppArmor/SELinux profile coverage. The interesting column is
//                  "unconfined AND network-reachable": that is the finding.
//
// The score is the agent's own weighted 0..100; the console does not recompute it,
// because a console that disagrees with the agent about posture is worse than no
// score. What the console adds is the per-item remediation button and the
// expected/actual pair.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import "../theme"
import "../components"

Item {
    id: page

    readonly property var h: backend.hardening
    // The bridge nests the audit under three keys: `boot` (Secure Boot, kernel
    // identity, bootloader, initramfs, trust score), `kernel_hardening` (sysctl
    // posture, lockdown, ASLR) and `mac` (LSM coverage and the daemon list).
    // The console must read them at those paths; guessing a flat layout is how a
    // page shows zeros for a fully-audited host.
    readonly property var boot: (page.h && page.h.boot) || {}
    readonly property var kernel: (page.h && page.h.boot && page.h.boot.kernel) || {}
    readonly property var secureBoot: (page.h && page.h.boot && page.h.boot.secure_boot) || {}
    readonly property var kernelHardening: (page.h && page.h.kernel_hardening) || {}
    readonly property var sysctls: page.kernelHardening.sysctls || []
    readonly property var mac: (page.h && page.h.mac) || {}

    // Local overrides for sysctl values, so the operator can stage a change and see
    // the diff before applying. Keyed by sysctl name.
    property var pending: ({})

    // trust_score lives under `boot`; compliant/drift are serialised as 0/1
    // integers by the bridge, not booleans, so compare against 1 explicitly.
    readonly property int trustScore: page.boot.trust_score !== undefined ? page.boot.trust_score : 0
    readonly property bool compliant: Number(page.kernelHardening.compliant || 0) > 0
    readonly property int driftCount: Number(page.kernelHardening.drift || 0)

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

            // ================= SCORE ======================================
            Panel {
                Layout.fillWidth: true
                Layout.preferredHeight: 120
                title: ""
                showAccent: false
                accentColor: Theme.riskColor((100 - page.trustScore) * 10)

                RowLayout {
                    anchors { fill: parent; margins: Theme.space4 }
                    spacing: Theme.space5

                    ColumnLayout {
                        Layout.alignment: Qt.AlignVCenter
                        spacing: 0
                        Label {
                            text: qsTr("BOOT & KERNEL TRUST")
                            color: Theme.textFaint
                            font { pixelSize: Theme.fontSizeMicro; family: Theme.fontFamily; weight: Theme.weightBold; letterSpacing: 1.4 }
                        }
                        RowLayout {
                            spacing: Theme.space2
                            Label {
                                text: page.trustScore
                                color: Theme.riskColor((100 - page.trustScore) * 10)
                                font { pixelSize: Theme.fontSizeHero; family: Theme.monoFamily; weight: Theme.weightBold }
                                Behavior on color { ColorAnimation { duration: Theme.animSlow } }
                            }
                            Label {
                                text: "/100"
                                color: Theme.textFaint
                                font.pixelSize: Theme.fontSizeBody
                                font.family: Theme.monoFamily
                                Layout.alignment: Qt.AlignBottom
                                Layout.bottomMargin: 10
                            }
                        }
                    }

                    Rectangle { Layout.preferredWidth: 1; Layout.fillHeight: true; color: Theme.border }

                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.alignment: Qt.AlignVCenter
                        spacing: Theme.space2

                        RowLayout {
                            spacing: Theme.space2
                            SevBadge {
                                text: page.compliant ? qsTr("compliant") : qsTr("drift detected")
                                customColor: page.compliant ? Theme.ok : Theme.medium
                            }
                            Label {
                                text: page.compliant
                                      ? qsTr("Every audited control matches its expected value.")
                                      : qsTr("%1 control(s) differ from the expected posture.").arg(page.driftCount)
                                color: Theme.textDim
                                font.pixelSize: Theme.fontSizeSmall
                                Layout.fillWidth: true
                                elide: Text.ElideRight
                            }
                        }

                        RowLayout {
                            spacing: Theme.space2
                            SevBadge {
                                text: page.secureBoot.enabled ? qsTr("secure boot") : qsTr("no secure boot")
                                customColor: page.secureBoot.enabled ? Theme.ok : Theme.critical
                            }
                            Label {
                                text: page.secureBoot.enabled
                                      ? qsTr("UEFI Secure Boot %1, %2").arg(page.secureBoot.enabled ? qsTr("enabled") : "?")
                                            .arg(page.secureBoot.setup_mode ? qsTr("setup mode") : qsTr("user mode"))
                                      : qsTr("Boot chain is not verifiable. On a VM this is expected unless EFI+SB is enabled.")
                                color: Theme.textDim
                                font.pixelSize: Theme.fontSizeSmall
                                Layout.fillWidth: true
                                elide: Text.ElideRight
                            }
                        }

                        RowLayout {
                            spacing: Theme.space2
                            SevBadge {
                                text: page.kernelHardening.lockdown_compliant ? qsTr("lockdown") : qsTr("no lockdown")
                                customColor: page.kernelHardening.lockdown_compliant ? Theme.ok : Theme.medium
                            }
                            Label {
                                text: page.kernel.release || ""
                                color: Theme.textDim
                                font.pixelSize: Theme.fontSizeSmall
                                font.family: Theme.monoFamily
                                Layout.fillWidth: true
                                elide: Text.ElideRight
                            }
                        }
                    }

                    Rectangle { Layout.preferredWidth: 1; Layout.fillHeight: true; color: Theme.border }

                    ColumnLayout {
                        Layout.alignment: Qt.AlignVCenter
                        spacing: Theme.space2
                        NovaButton {
                            text: qsTr("Re-audit")
                            role: "secondary"
                            onTriggered: backend.rescanHardening()
                        }
                        NovaButton {
                            text: qsTr("Apply all remediations")
                            role: "primary"
                            confirm: true
                            enabled: page.driftCount > 0
                            onTriggered: backend.hardenAll()
                            ToolTip.visible: hovered
                            ToolTip.text: qsTr("Write every remediation the audit suggests to /proc/sys " +
                                               "and verify the read-back. Reversible: the previous value " +
                                               "is in the report.")
                        }
                    }
                }
            }

            // ================= BOOT TRUST =================================
            Panel {
                Layout.fillWidth: true
                Layout.preferredHeight: bootList.height + 76
                title: qsTr("Boot chain")
                subtitle: qsTr("what the audit could and could not verify")
                glyph: "\u26BF"
                ListView {
                    id: bootList
                    anchors { left: parent.left; right: parent.right; bottom: parent.bottom }
                    height: Math.min(contentHeight, 260)
                    model: page.bootFindings
                    spacing: 2
                    clip: true
                    interactive: false
                    boundsBehavior: Flickable.StopAtBounds

                    delegate: RowLayout {
                        required property var modelData
                        width: ListView.view.width
                        spacing: Theme.space3

                        GlowDot {
                            size: 8
                            color: modelData.ok ? Theme.ok : (modelData.critical ? Theme.critical : Theme.medium)
                            glow: !modelData.ok
                        }
                        Label {
                            text: modelData.name
                            color: Theme.textDim
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            Layout.preferredWidth: 220
                        }
                        Label {
                            text: modelData.value
                            color: modelData.ok ? Theme.text : Theme.text
                            font.pixelSize: Theme.fontSizeSmall
                            font.family: Theme.monoFamily
                            Layout.fillWidth: true
                            elide: Text.ElideRight
                        }
                    }
                }

                EmptyState {
                    anchors.centerIn: parent
                    visible: page.bootFindings.length === 0
                    message: qsTr("No boot audit data")
                    hint: qsTr("Run the agent as root for a full audit; as a user it can only read public state.")
                }
            }

            // ================= KERNEL SYSCTLS =============================
            Panel {
                Layout.fillWidth: true
                Layout.preferredHeight: sysctlList.height + 110
                title: qsTr("Kernel posture")
                subtitle: qsTr("%1 controls \u00B7 click a row to stage a change, then Apply")
                          .arg(page.sysctls.length)
                glyph: "\u2699"
                accentColor: page.driftCount > 0 ? Theme.medium : Theme.ok
                headerRight: RowLayout {
                    spacing: Theme.space2
                    Label {
                        text: qsTr("%1 pending").arg(Object.keys(page.pending).length)
                        visible: Object.keys(page.pending).length > 0
                        color: Theme.medium
                        font.pixelSize: Theme.fontSizeSmall
                        font.family: Theme.monoFamily
                    }
                    NovaButton {
                        text: qsTr("Apply staged")
                        role: "primary"
                        compact: true
                        visible: Object.keys(page.pending).length > 0
                        onTriggered: {
                            var keys = Object.keys(page.pending);
                            for (var i = 0; i < keys.length; ++i)
                                backend.harden(keys[i], page.pending[keys[i]]);
                            page.pending = {};
                        }
                    }
                    NovaButton {
                        text: qsTr("Discard")
                        role: "ghost"
                        compact: true
                        visible: Object.keys(page.pending).length > 0
                        onTriggered: page.pending = {}
                    }
                }

                ListView {
                    id: sysctlList
                    anchors { left: parent.left; right: parent.right; bottom: parent.bottom }
                    height: Math.min(contentHeight, 380)
                    model: page.sysctls
                    spacing: 2
                    clip: true
                    boundsBehavior: Flickable.StopAtBounds
                    reuseItems: true

                    delegate: Rectangle {
                        id: sRow
                        required property var modelData
                        readonly property string key: modelData.name || ""
                        readonly property string expected: String(modelData.expected !== undefined ? modelData.expected : "")
                        readonly property string actual: String(modelData.actual !== undefined ? modelData.actual : "")
                        readonly property bool drift: sRow.expected !== sRow.actual
                        readonly property bool staged: page.pending[sRow.key] !== undefined
                        readonly property string shown: sRow.staged ? page.pending[sRow.key] : sRow.actual

                        width: ListView.view.width
                        height: 40
                        radius: Theme.radiusSm
                        color: sHover.containsMouse ? Theme.surfaceAlt
                             : sRow.drift ? Theme.withAlpha(Theme.medium, 0.06) : "transparent"
                        border.width: sRow.staged ? 1 : 0
                        border.color: Theme.withAlpha(Theme.accent, 0.6)

                        RowLayout {
                            anchors { fill: parent; leftMargin: Theme.space3; rightMargin: Theme.space3 }
                            spacing: Theme.space3

                            SevBadge {
                                text: sRow.drift ? qsTr("drift") : qsTr("ok")
                                customColor: sRow.drift ? Theme.medium : Theme.ok
                            }
                            Label {
                                text: sRow.key
                                color: Theme.text
                                font.pixelSize: Theme.fontSizeSmall
                                font.family: Theme.monoFamily
                                Layout.preferredWidth: 280
                                elide: Text.ElideRight
                            }
                            Label {
                                text: qsTr("expected %1").arg(sRow.expected)
                                color: Theme.textFaint
                                font.pixelSize: Theme.fontSizeSmall
                                font.family: Theme.monoFamily
                                Layout.preferredWidth: 110
                            }
                            Label {
                                text: sRow.shown
                                color: sRow.staged ? Theme.accent
                                     : sRow.drift ? Theme.medium : Theme.textDim
                                font.pixelSize: Theme.fontSizeSmall
                                font.family: Theme.monoFamily
                                Layout.preferredWidth: 80
                            }
                            Item {
                                Layout.fillWidth: true
                                TextField {
                                    id: edit
                                    anchors { right: parent.right; verticalCenter: parent.verticalCenter }
                                    width: 80
                                    text: sRow.actual
                                    color: Theme.text
                                    font.pixelSize: Theme.fontSizeSmall
                                    font.family: Theme.monoFamily
                                    background: Rectangle {
                                        radius: Theme.radiusSm
                                        color: Theme.surfaceAlt
                                        border.width: 1
                                        border.color: edit.activeFocus ? Theme.accent : Theme.border
                                    }
                                    onEditingFinished: {
                                        var p = Object.assign({}, page.pending);
                                        if (edit.text === sRow.expected) delete p[sRow.key];
                                        else p[sRow.key] = edit.text;
                                        page.pending = p;
                                    }
                                }
                            }
                            NovaButton {
                                text: qsTr("Apply")
                                role: "secondary"
                                compact: true
                                onTriggered: backend.harden(sRow.key, edit.text)
                            }
                        }

                        HoverHandler { id: sHover }
                        ToolTip.visible: sHover.containsMouse
                        ToolTip.text: sRow.modelData.rationale || sRow.modelData.remediation || ""
                        // (attached ToolTip has no wrapMode; newlines in the text still break)
                    }
                }

                EmptyState {
                    anchors.centerIn: parent
                    visible: page.sysctls.length === 0
                    message: qsTr("No sysctl findings")
                    hint: qsTr("The hardening audit has not run, or it could not read /proc/sys.")
                }
            }

            // ================= MAC ========================================
            Panel {
                Layout.fillWidth: true
                Layout.preferredHeight: macList.height + 76
                title: qsTr("Mandatory access control")
                subtitle: qsTr("unconfined AND network-reachable is the finding that matters")
                glyph: "\u26BF"
                ListView {
                    id: macList
                    anchors { left: parent.left; right: parent.right; bottom: parent.bottom }
                    height: Math.min(contentHeight, 300)
                    model: page.macRows
                    spacing: 2
                    clip: true
                    boundsBehavior: Flickable.StopAtBounds
                    reuseItems: true

                    delegate: Rectangle {
                        id: mRow
                        required property var modelData
                        readonly property bool unconfined: mRow.modelData.mode === "unconfined"
                                                          || mRow.modelData.confined === false
                        readonly property bool reachable: mRow.modelData.network_reachable === true
                        readonly property bool bad: mRow.unconfined && mRow.reachable

                        width: ListView.view.width
                        height: 38
                        radius: Theme.radiusSm
                        color: mHover.containsMouse ? Theme.surfaceAlt
                             : mRow.bad ? Theme.withAlpha(Theme.critical, 0.07) : "transparent"

                        RowLayout {
                            anchors { fill: parent; leftMargin: Theme.space3; rightMargin: Theme.space3 }
                            spacing: Theme.space3

                            GlowDot {
                                size: 8
                                color: mRow.bad ? Theme.critical
                                     : mRow.unconfined ? Theme.medium : Theme.ok
                                glow: mRow.bad
                                pulse: mRow.bad
                            }
                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: 0
                                Label {
                                    text: mRow.modelData.profile || mRow.modelData.name || "?"
                                    color: Theme.text
                                    font { pixelSize: Theme.fontSizeBody; family: Theme.monoFamily; weight: Theme.weightMedium }
                                    elide: Text.ElideRight
                                    Layout.fillWidth: true
                                }
                                Label {
                                    text: mRow.modelData.profile || ""
                                    color: Theme.textFaint
                                    font.pixelSize: Theme.fontSizeMicro
                                    font.family: Theme.monoFamily
                                    elide: Text.ElideRight
                                    Layout.fillWidth: true
                                }
                            }
                            SevBadge {
                                text: mRow.bad ? qsTr("unconfined + reachable")
                                     : mRow.unconfined ? qsTr("unconfined")
                                     : mRow.modelData.mode || "enforce"
                                customColor: mRow.bad ? Theme.critical : mRow.unconfined ? Theme.medium : Theme.ok
                            }
                            Label {
                                text: qsTr("%1 pids").arg((mRow.modelData.pids || []).length)
                                color: Theme.textDim
                                font.pixelSize: Theme.fontSizeSmall
                                font.family: Theme.monoFamily
                                Layout.preferredWidth: 70
                                horizontalAlignment: Text.AlignRight
                            }
                            Label {
                                text: (mRow.modelData.ports || []).join(", ")
                                color: Theme.textFaint
                                font.pixelSize: Theme.fontSizeSmall
                                font.family: Theme.monoFamily
                                Layout.preferredWidth: 100
                                horizontalAlignment: Text.AlignRight
                                elide: Text.ElideRight
                            }
                        }

                        HoverHandler { id: mHover }
                        ToolTip.visible: mHover.containsMouse
                        ToolTip.text: {
                            var m = mRow.modelData;
                            return qsTr("daemon %1 \u00B7 profile %2 \u00B7 mode %3 \u00B7 %4 pids \u00B7 ports %5 \u00B7 reachable %6")
                                     .arg(m.name || "?").arg(m.profile || "?").arg(m.mode || "?")
                                     .arg((m.pids || []).length)
                                     .arg((m.ports || []).join(", ") || qsTr("none"))
                                     .arg(m.network_reachable ? qsTr("yes") : qsTr("no"));
                        }
                    }
                }

                EmptyState {
                    anchors.centerIn: parent
                    visible: page.macRows.length === 0
                    message: qsTr("No MAC profiles loaded")
                    hint: qsTr("Neither AppArmor nor SELinux reported any profiles. " +
                               "On a host with neither, every process is unconfined by definition.")
                }
            }
        }
    }

    /// Normalised boot findings: one row per check, with ok/critical flags derived
    /// from the agent's structured fields rather than from free text.
    readonly property var bootFindings: {
        var sb = page.secureBoot;
        var k = page.kernel;
        var bl = page.boot.bootloader || {};
        var ir = page.boot.initramfs || [];
        var out = [];
        function add(name, value, ok, critical) {
            out.push({ name: name, value: value, ok: !!ok, critical: !!critical });
        }
        add(qsTr("UEFI"), sb.uefi === true ? qsTr("yes") : qsTr("no (legacy BIOS)"),
            sb.uefi === true, sb.uefi !== true);
        add(qsTr("Secure Boot"), sb.enabled === true ? qsTr("enabled") : qsTr("disabled"),
            sb.enabled === true, sb.enabled !== true);
        add(qsTr("Setup mode"), sb.setup_mode === true ? qsTr("SETUP MODE \u2014 keys not enrolled") : qsTr("user mode"),
            sb.setup_mode !== true, sb.setup_mode === true);
        add(qsTr("MOK list"), sb.mok_list === true ? qsTr("present") : qsTr("absent"), true, false);
        add(qsTr("sbctl"), sb.sbctl_status || qsTr("not installed"), sb.sbctl === true, false);
        add(qsTr("Kernel"), k.release || "?", true, false);
        add(qsTr("LTS kernel"), k.lts === true ? qsTr("yes") : qsTr("no"), k.lts === true, k.lts !== true);
        add(qsTr("Hardened flavour"), k.hardened_flavour === true ? qsTr("yes") : qsTr("no"),
            k.hardened_flavour === true, false);
        add(qsTr("Tainted"), k.tainted === true ? (k.taint_meanings || []).join(", ") : qsTr("clean"),
            k.tainted !== true, k.tainted === true);
        add(qsTr("Module signatures"), k.module_sig_enforced === true ? qsTr("enforced") : qsTr("not enforced"),
            k.module_sig_enforced === true, k.module_sig_enforced !== true);
        add(qsTr("Lockdown"), page.kernelHardening.lockdown_compliant ? qsTr("confined") : qsTr("not confined"),
            page.kernelHardening.lockdown_compliant === true,
            page.kernelHardening.lockdown_compliant !== true);
        // initramfs is an ARRAY of images, each with its own integrity result.
        // Showing the count and the worst verdict is more honest than stringifying
        // the array.
        var irChanged = 0;
        for (var i = 0; i < ir.length; ++i) if (ir[i].changed === true) irChanged++;
        add(qsTr("Initramfs"), ir.length > 0
                ? qsTr("%1 image(s), %2 changed since baseline").arg(ir.length).arg(irChanged)
                : qsTr("not audited"),
            ir.length === 0 || irChanged === 0, irChanged > 0);
        add(qsTr("Bootloader"), bl.flavour || qsTr("unknown"),
            bl.world_writable_config !== true, bl.world_writable_config === true);
        return out;
    }

    /// Normalised MAC rows. The bridge's `mac` object carries a `daemons` array:
    /// every network-reachable daemon the audit knows about, each with its profile,
    /// mode, pids and listen ports. That array IS the finding list — an unconfined
    /// sshd is a row with mode "unconfined", not a separate list.
    readonly property var macRows: {
        var m = page.mac;
        var out = [];
        var ds = m.daemons || [];
        for (var i = 0; i < ds.length; ++i) out.push(ds[i]);
        // Worst first: unconfined-and-reachable, then unconfined, then confined.
        // `confined` is a bool on the daemon row; `mode` is its string form.
        out.sort(function(a, b) {
            function rank(r) {
                var unconfined = r.mode === "unconfined" || r.confined === false;
                return (unconfined && r.network_reachable === true) ? 0
                     : unconfined ? 1 : 2;
            }
            return rank(a) - rank(b);
        });
        return out;
    }
}
