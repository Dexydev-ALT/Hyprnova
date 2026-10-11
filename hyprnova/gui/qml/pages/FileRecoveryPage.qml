// SPDX-License-Identifier: Apache-2.0
// HyprNova :: File recovery page -- put good bytes back where they belong.
//
// Two honest paths:
//   1. shadow-copy restore: restore a verified snapshot's files into place
//      (root-gated on the daemon side; the refusal is shown verbatim),
//   2. quarantine restore: release a quarantined sample back to its original
//      (or an operator-chosen) destination. The engine re-verifies the sha256
//      recorded at quarantine time and refuses tampered samples regardless of
//      what this UI asks for.
// Both write host state: every button here asks for confirmation first.

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
    readonly property bool replyIsRestore: String(reply.cmd || "") === "restore_shadow"
    readonly property int quarCount: (backend.remediationActions || []).length

    Component.onCompleted: {
        backend.refreshSnapshots();
        backend.refreshRemediation();
    }

    ColumnLayout {
        anchors {
            fill: parent
            leftMargin: Theme.space5; rightMargin: Theme.space5
            topMargin: Theme.space4; bottomMargin: Theme.space4
        }
        spacing: Theme.space3

        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.space3
            SectionTitle {
                Layout.fillWidth: true
                text: qsTr("File recovery")
                detail: qsTr("restore from a verified shadow copy — or release a quarantined sample")
            }
            NovaButton {
                text: qsTr("Refresh")
                role: "ghost"; compact: true
                onClicked: { backend.refreshSnapshots(); backend.refreshRemediation(); }
            }
        }

        // ---- shadow restore ----------------------------------------------------
        Panel {
            Layout.fillWidth: true
            title: qsTr("Restore a shadow copy")
            glyph: "\u21F3"

            ColumnLayout {
                width: parent.width
                spacing: Theme.space2

                Label {
                    width: parent.width
                    wrapMode: Text.Wrap
                    color: Theme.textDim
                    font.pixelSize: Theme.fontSizeSmall
                    text: qsTr("Pick a snapshot id (listed below) and a destination directory " +
                               "(empty = the snapshot's original roots). Restoring overwrites " +
                               "current files with the snapshotted copies — that is the point, " +
                               "and why this asks twice.")
                }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.space2
                    Label { text: qsTr("snapshot:"); color: Theme.textDim }
                    TextField {
                        id: snapId
                        Layout.preferredWidth: 230
                        font.family: "monospace"
                        placeholderText: page.snaps.length > 0
                                         ? String(page.snaps[0].id || page.snaps[0] || "")
                                         : qsTr("none yet")
                    }
                    Label { text: qsTr("to:"); color: Theme.textDim }
                    TextField {
                        id: snapDest
                        Layout.fillWidth: true
                        placeholderText: qsTr("destination dir (optional)")
                    }
                    // Two-step confirm is built into NovaButton (confirm: true):
                    // first click arms, second click fires onClicked.
                    NovaButton {
                        text: qsTr("Restore…")
                        role: "danger"
                        confirm: true
                        enabled: snapId.text.trim().length > 0
                        onClicked: backend.restoreShadow(snapId.text.trim(), snapDest.text.trim())
                    }
                }

                Label {
                    visible: page.replyIsRestore
                    width: parent.width
                    wrapMode: Text.Wrap
                    color: page.reply.ok === false ? Theme.high : Theme.good
                    text: page.replyIsRestore
                          ? (String(page.reply.error || "").length > 0
                             ? String(page.reply.error)
                             : qsTr("restored %1, verified %2, failed %3 — detail: %4")
                                   .arg(String(page.reply.restored ?? "?"))
                                   .arg(String(page.reply.verified ?? "?"))
                                   .arg(String(page.reply.failed ?? "?"))
                                   .arg(String(page.reply.detail || "")))
                          : ""
                }
            }
        }

        // ---- quarantine release ---------------------------------------------------
        Panel {
            Layout.fillWidth: true
            title: qsTr("Release a quarantined file")
            glyph: "\u2731"

            ColumnLayout {
                width: parent.width
                spacing: Theme.space2

                Label {
                    width: parent.width
                    wrapMode: Text.Wrap
                    color: Theme.textDim
                    font.pixelSize: Theme.fontSizeSmall
                    text: qsTr("The engine re-verifies the sha256 recorded at quarantine time and " +
                               "refuses a tampered sample even with force. Force is only needed " +
                               "when the original destination is occupied again.")
                }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.space2
                    Label { text: qsTr("id:"); color: Theme.textDim }
                    TextField {
                        id: qId
                        Layout.preferredWidth: 110
                        validator: IntValidator { bottom: 1 }
                    }
                    Label { text: qsTr("to:"); color: Theme.textDim }
                    TextField {
                        id: qDest
                        Layout.fillWidth: true
                        placeholderText: qsTr("full destination path")
                    }
                    CheckBox {
                        id: qForce
                        text: qsTr("force over occupied destination")
                        contentItem: Label {
                            text: qForce.text
                            color: Theme.textDim
                            font.pixelSize: Theme.fontSizeSmall
                            leftPadding: qForce.indicator.width + qForce.spacing
                            verticalAlignment: Text.AlignVCenter
                        }
                    }
                    NovaButton {
                        text: qsTr("Restore…")
                        role: "danger"
                        confirm: true
                        enabled: qId.text.length > 0
                        onClicked: backend.restore(parseInt(qId.text, 10), qDest.text.trim())
                    }
                }

                Label {
                    width: parent.width
                    wrapMode: Text.Wrap
                    color: Theme.textDim
                    font.pixelSize: Theme.fontSizeSmall
                    text: qsTr("%1 quarantined entr(y|ies) right now — ids and rows on the Remediation page.")
                          .arg(page.quarCount)
                }
            }
        }

        // ---- snapshot picker ---------------------------------------------------------
        Panel {
            Layout.fillWidth: true
            Layout.fillHeight: true
            title: qsTr("Available snapshots")

            ColumnLayout {
                width: parent.width
                spacing: Theme.space1

                EmptyState {
                    visible: page.snaps.length === 0
                    message: qsTr("No snapshots to restore from")
                    hint: qsTr("Create one on the Backups page — recovery needs a verified copy first.")
                }

                Repeater {
                    model: page.snaps
                    delegate: RowLayout {
                        required property var modelData
                        width: parent.width
                        spacing: Theme.space2
                        GlowDot { size: 8; color: Theme.good }
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
                            text: qsTr("Use id")
                            role: "ghost"; compact: true
                            onClicked: snapId.text = String(modelData.id || modelData || "")
                        }
                    }
                }
            }
        }
    }
}
