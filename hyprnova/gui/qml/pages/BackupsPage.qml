// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Backups page -- the shadow-copy lifeline (Module: recovery).
//
// List what is snapshotted, take a fresh one, verify an existing one against
// its manifest. Restoration lives on File recovery; this page is the read-most
// view plus the create/verify actions. Snapshot creation is root-gated on the
// daemon side: an unprivileged console gets the daemon's own refusal, shown
// here verbatim.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../theme"
import "../components"

Page {
    id: page

    property int pageIndex: 0

    background: Item {}

    readonly property var snaps: {
        var s = backend.snapshots || [];
        var out = [];
        for (var i = 0; i < s.length; ++i) out.push(s[i]);
        return out;
    }
    readonly property var reply: backend.snapshotReply || {}
    readonly property bool replyIsSnapshot: String(reply.cmd || "") === "snapshot"
    readonly property bool replyIsVerify: String(reply.cmd || "") === "verify_snapshot"

    Component.onCompleted: backend.refreshSnapshots()

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
                text: qsTr("Shadow-copy backups")
                detail: qsTr("the ransomware lifeline — verified copies outside the attacker's reach")
            }
            NovaButton {
                text: qsTr("Refresh")
                role: "ghost"; compact: true
                onClicked: backend.refreshSnapshots()
            }
        }

        // ---- create ----------------------------------------------------------
        Panel {
            Layout.fillWidth: true
            title: qsTr("Take a snapshot now")
            glyph: "\u271A"

            ColumnLayout {
                width: parent.width
                spacing: Theme.space2

                Label {
                    width: parent.width
                    wrapMode: Text.Wrap
                    color: Theme.textDim
                    font.pixelSize: Theme.fontSizeSmall
                    text: qsTr("Snapshots are content-addressed and verified against a manifest. " +
                               "Requires root on the agent socket; otherwise the daemon's refusal " +
                               "is shown below unchanged.")
                }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.space2
                    TextField {
                        id: snapReason
                        Layout.fillWidth: true
                        placeholderText: qsTr("reason (stored with the snapshot)")
                    }
                    NovaButton {
                        text: qsTr("Snapshot")
                        role: "primary"
                        onClicked: backend.createSnapshot(
                                       snapReason.text.trim().length > 0
                                           ? snapReason.text.trim()
                                           : "operator request from the console")
                    }
                }
            }
        }

        // ---- last action feedback ---------------------------------------------
        Panel {
            Layout.fillWidth: true
            visible: Object.keys(page.reply).length > 0
            title: page.replyIsVerify ? qsTr("Verification result")
                  : page.replyIsSnapshot ? qsTr("Snapshot result")
                  : qsTr("Last action")
            accentColor: page.reply.ok === false ? Theme.high : Theme.good

            ColumnLayout {
                width: parent.width
                spacing: Theme.space1

                Label {
                    visible: String(page.reply.error || "").length > 0
                    width: parent.width
                    wrapMode: Text.Wrap
                    color: Theme.high
                    text: String(page.reply.error || "")
                }
                Label {
                    visible: page.replyIsVerify
                    width: parent.width
                    wrapMode: Text.Wrap
                    color: page.reply.verified === true ? Theme.good : Theme.high
                    text: page.replyIsVerify
                          ? (page.reply.verified === true
                             ? qsTr("snapshot %1 verified: %2").arg(String(page.reply.id || ""))
                                                      .arg(String(page.reply.detail || ""))
                             : qsTr("snapshot %1 FAILED verification: %2")
                                   .arg(String(page.reply.id || ""))
                                   .arg(String(page.reply.detail || "")))
                          : ""
                }
                Label {
                    visible: page.replyIsSnapshot && page.reply.ok === true
                    width: parent.width
                    wrapMode: Text.Wrap
                    color: Theme.text
                    text: qsTr("created: %1 — %2").arg(String(page.reply.id || ""))
                                                   .arg(String(page.reply.detail || ""))
                }
            }
        }

        // ---- list ---------------------------------------------------------------
        Panel {
            Layout.fillWidth: true
            Layout.fillHeight: true
            title: qsTr("Existing snapshots")
            subtitle: qsTr("%1 on this host").arg(page.snaps.length)

            ColumnLayout {
                width: parent.width
                spacing: Theme.space1

                EmptyState {
                    visible: page.snaps.length === 0
                    message: qsTr("No snapshots yet — take one now")
                    hint: qsTr("Recovery is only as good as the newest verified copy.")
                }

                Repeater {
                    model: page.snaps
                    delegate: RowLayout {
                        required property var modelData
                        width: parent.width
                        spacing: Theme.space2

                        GlowDot { size: 8; color: Theme.accent }
                        Label {
                            Layout.preferredWidth: 210
                            color: Theme.text
                            font.family: "monospace"
                            font.pixelSize: Theme.fontSizeSmall
                            elide: Text.ElideMiddle
                            text: String(modelData.id || modelData || "?")
                        }
                        Label {
                            Layout.fillWidth: true
                            color: Theme.textDim
                            font.pixelSize: Theme.fontSizeSmall
                            elide: Text.ElideRight
                            text: String(modelData.reason || modelData.detail || "")
                        }
                        NovaButton {
                            text: qsTr("Verify")
                            role: "ghost"; compact: true
                            onClicked: backend.verifySnapshot(
                                           String(modelData.id || modelData || ""))
                        }
                    }
                }
            }
        }
    }
}
