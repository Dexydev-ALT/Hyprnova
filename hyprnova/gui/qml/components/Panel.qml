// SPDX-License-Identifier: Apache-2.0
// HyprNova :: panel — the card every page is built from
//
// A titled surface with a hairline border, an optional accent rule, and a slot for
// header-right controls. `default property alias content` means pages write
//
//     Panel { title: "Live feed"; Label { ... } }
//
// rather than nesting into a `contentItem`, which keeps page files readable.

import QtQuick
import QtQuick.Controls
import "../theme"

Rectangle {
    id: root

    property string title: ""
    property string subtitle: ""
    /// Optional icon glyph (text, not an image: no asset pipeline, no scaling bug).
    property string glyph: ""
    /// Colour of the 2 px rule under the header. Defaults to the accent; pages
    /// override it to a severity colour when the panel is in an alert state.
    property color accentColor: Theme.accent
    /// Draw the accent rule at all. Off for dense sub-panels.
    property bool showAccent: true
    /// Header-right slot: refresh buttons, filters, counts.
    property alias headerRight: headerRightRow.data
    /// Body padding.
    property int pad: Theme.space4
    /// Body slot.
    default property alias content: body.data

    color: Theme.surface
    radius: Theme.radiusMd
    // A 1 px border in a slightly lighter tone than the fill is what separates
    // cards on a dark background; a shadow would need a layer and looks muddy.
    border.width: 1
    border.color: Theme.border

    implicitHeight: header.height + (showAccent ? 2 : 0) + body.implicitHeight + pad * 2
    implicitWidth: Theme.cardMinWidth

    Column {
        id: header
        anchors { left: parent.left; right: parent.right; top: parent.top; margins: pad }
        spacing: 2
        visible: root.title.length > 0 || headerRightRow.children.length > 0

        Row {
            width: parent.width
            spacing: Theme.space2

            Label {
                text: root.glyph
                font.pixelSize: Theme.fontSizeLarge
                color: root.accentColor
                visible: root.glyph.length > 0
                verticalAlignment: Text.AlignVCenter
                anchors.verticalCenter: parent.verticalCenter
            }

            Column {
                width: parent.width - (root.glyph.length > 0 ? Theme.space2 + Theme.fontSizeLarge : 0)
                                        - headerRightRow.width - Theme.space2
                spacing: 0
                anchors.verticalCenter: parent.verticalCenter

                Label {
                    text: root.title
                    visible: root.title.length > 0
                    color: Theme.text
                    font {
                        pixelSize: Theme.fontSizeLarge
                        weight: Theme.weightMedium
                        family: Theme.fontFamily
                        letterSpacing: 0.2
                    }
                    elide: Text.ElideRight
                    width: parent.width
                }
                Label {
                    text: root.subtitle
                    visible: root.subtitle.length > 0
                    color: Theme.textFaint
                    font.pixelSize: Theme.fontSizeSmall
                    font.family: Theme.fontFamily
                    elide: Text.ElideRight
                    width: parent.width
                }
            }

            Row {
                id: headerRightRow
                spacing: Theme.space2
                anchors.verticalCenter: parent.verticalCenter
            }
        }
    }

    Rectangle {
        id: accentRule
        anchors { left: parent.left; right: parent.right; top: header.bottom; topMargin: Theme.space3 }
        height: 2
        visible: root.showAccent && header.visible
        // Fades out to the right: a full-width saturated rule competes with the
        // severity colours that carry actual meaning.
        gradient: Gradient {
            orientation: Gradient.Horizontal
            GradientStop { position: 0.0; color: Theme.withAlpha(root.accentColor, 0.85) }
            GradientStop { position: 0.35; color: Theme.withAlpha(root.accentColor, 0.25) }
            GradientStop { position: 1.0; color: "transparent" }
        }
    }

    Item {
        id: body
        anchors {
            left: parent.left
            right: parent.right
            top: root.showAccent && header.visible ? accentRule.bottom : header.bottom
            bottom: parent.bottom
            margins: pad
            topMargin: Theme.space3
        }
        implicitHeight: childrenRect.height
    }
}
