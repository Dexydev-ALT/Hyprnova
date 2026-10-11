// SPDX-License-Identifier: Apache-2.0
// HyprNova :: NavIcon -- vector line icons drawn on a Canvas.
//
// Why Canvas rather than a font glyph or an SVG asset: glyphs depend on which
// fonts the host happens to have (an EDR console runs on everything from a
// workstation to a stripped VM), and Image/SVG silently needs the Qt SVG image
// format plugin which is a separate package. A Canvas is guaranteed, scales with
// `size`, and repaints exactly once.

import QtQuick

Canvas {
    id: icon

    /// Icon name. Unknown names render the dot fallback rather than throwing.
    property string name: "dot"
    property color color: "#9AA6B6"
    property real strokeW: 1.6

    implicitWidth: 18
    implicitHeight: 18
    antialiasing: true
    renderStrategy: Canvas.Immediate

    onNameChanged: requestPaint()
    onColorChanged: requestPaint()
    onWidthChanged: requestPaint()

    onPaint: {
        var ctx = getContext("2d");
        ctx.reset();
        ctx.clearRect(0, 0, width, height);
        ctx.strokeStyle = String(icon.color);
        ctx.fillStyle = String(icon.color);
        ctx.lineWidth = strokeW;
        ctx.lineCap = "round";
        ctx.lineJoin = "round";

        var s = Math.min(width, height);
        var o = (width - s) / 2, v = (height - s) / 2;
        // Normalise to an 18x18 design grid.
        var k = s / 18.0;
        ctx.scale(k, k);
        ctx.translate(o / k, v / k);

        switch (name) {
        case "home":
            ctx.beginPath();
            ctx.moveTo(2.5, 8.5); ctx.lineTo(9, 2.5); ctx.lineTo(15.5, 8.5);
            ctx.moveTo(4.5, 7.5); ctx.lineTo(4.5, 15); ctx.lineTo(13.5, 15);
            ctx.lineTo(13.5, 7.5);
            ctx.stroke();
            break;
        case "shield":
            ctx.beginPath();
            ctx.moveTo(9, 2); ctx.lineTo(15, 4.4); ctx.lineTo(15, 9);
            ctx.quadraticCurveTo(15, 14, 9, 16);
            ctx.quadraticCurveTo(3, 14, 3, 9); ctx.lineTo(3, 4.4); ctx.closePath();
            ctx.stroke();
            ctx.beginPath();
            ctx.moveTo(6.4, 9); ctx.lineTo(8.3, 10.9); ctx.lineTo(11.8, 6.9);
            ctx.stroke();
            break;
        case "warning":
            ctx.beginPath();
            ctx.moveTo(9, 2.5); ctx.lineTo(16, 15); ctx.lineTo(2, 15); ctx.closePath();
            ctx.stroke();
            ctx.beginPath();
            ctx.moveTo(9, 7); ctx.lineTo(9, 10.6); ctx.stroke();
            ctx.beginPath();
            ctx.arc(9, 12.9, 0.4, 0, Math.PI * 2); ctx.fill();
            break;
        case "processes":
            ctx.beginPath();
            ctx.moveTo(3, 4.5); ctx.lineTo(15, 4.5);
            ctx.moveTo(3, 9);   ctx.lineTo(15, 9);
            ctx.moveTo(3, 13.5);ctx.lineTo(15, 13.5);
            ctx.stroke();
            break;
        case "network":
            ctx.beginPath();
            ctx.arc(9, 3.6, 1.6, 0, Math.PI * 2); ctx.stroke();
            ctx.beginPath();
            ctx.arc(3.6, 13.5, 1.6, 0, Math.PI * 2); ctx.stroke();
            ctx.beginPath();
            ctx.arc(14.4, 13.5, 1.6, 0, Math.PI * 2); ctx.stroke();
            ctx.beginPath();
            ctx.moveTo(9, 5.2); ctx.lineTo(9, 9); ctx.moveTo(9, 9);
            ctx.lineTo(4.5, 12.2); ctx.moveTo(9, 9); ctx.lineTo(13.5, 12.2);
            ctx.stroke();
            break;
        case "scan":
            ctx.beginPath();
            ctx.arc(8, 8, 5, 0, Math.PI * 2); ctx.stroke();
            ctx.beginPath();
            ctx.moveTo(11.8, 11.8); ctx.lineTo(15.5, 15.5); ctx.stroke();
            break;
        case "hardening":
            // anvil-ish: a wrench
            ctx.beginPath();
            ctx.moveTo(4, 14); ctx.lineTo(10.5, 7.5); ctx.stroke();
            ctx.beginPath();
            ctx.arc(12.6, 5.4, 2.6, Math.PI * 0.15, Math.PI * 1.35);
            ctx.stroke();
            ctx.beginPath();
            ctx.arc(12.6, 5.4, 1.0, Math.PI * 1.1, Math.PI * 2.1);
            ctx.stroke();
            ctx.beginPath();
            ctx.arc(3.6, 14.4, 1.4, Math.PI * 0.8, Math.PI * 1.9);
            ctx.stroke();
            break;
        case "canaries":
            ctx.beginPath();
            ctx.arc(9, 9, 6.2, 0, Math.PI * 2); ctx.stroke();
            ctx.beginPath();
            ctx.arc(9, 9, 2.3, 0, Math.PI * 2); ctx.stroke();
            break;
        case "remediation":
            ctx.beginPath();
            ctx.moveTo(9, 2.4); ctx.lineTo(9, 7.4); ctx.stroke();
            ctx.beginPath();
            ctx.moveTo(4.6, 4.2); ctx.lineTo(7.4, 8.2); ctx.stroke();
            ctx.beginPath();
            ctx.moveTo(13.4, 4.2); ctx.lineTo(10.6, 8.2); ctx.stroke();
            ctx.beginPath();
            ctx.arc(9, 10.9, 4.2, 0, Math.PI * 2); ctx.stroke();
            ctx.beginPath();
            ctx.arc(9, 10.9, 1.1, 0, Math.PI * 2); ctx.fill();
            break;
        case "tools":
            ctx.beginPath();
            ctx.rect(2.5, 3, 13, 3.4); ctx.stroke();
            ctx.beginPath();
            ctx.rect(2.5, 11.6, 13, 3.4); ctx.stroke();
            ctx.beginPath();
            ctx.arc(7, 4.7, 0.6, 0, Math.PI * 2); ctx.fill();
            ctx.beginPath();
            ctx.arc(11, 13.3, 0.6, 0, Math.PI * 2); ctx.fill();
            break;
        case "settings":
            ctx.beginPath();
            ctx.arc(9, 9, 2.2, 0, Math.PI * 2); ctx.stroke();
            for (var i = 0; i < 8; i++) {
                var a = i * Math.PI / 4;
                ctx.beginPath();
                ctx.moveTo(9 + Math.cos(a) * 4.2, 9 + Math.sin(a) * 4.2);
                ctx.lineTo(9 + Math.cos(a) * 6.4, 9 + Math.sin(a) * 6.4);
                ctx.stroke();
            }
            break;
        case "search":
            ctx.beginPath();
            ctx.arc(8, 8, 5, 0, Math.PI * 2); ctx.stroke();
            ctx.beginPath();
            ctx.moveTo(11.8, 11.8); ctx.lineTo(15.5, 15.5); ctx.stroke();
            break;
        case "help":
            ctx.font = "bold 13px sans-serif";
            ctx.textAlign = "center";
            ctx.textBaseline = "middle";
            ctx.fillText("?", 9, 10);
            break;
        case "minimize":
            ctx.beginPath();
            ctx.moveTo(4, 9); ctx.lineTo(14, 9); ctx.stroke();
            break;
        case "maximize":
            ctx.strokeRect(4.5, 4.5, 9, 9);
            break;
        case "restore":
            ctx.strokeRect(4.5, 6.5, 7, 7);
            ctx.beginPath();
            ctx.moveTo(6.5, 6.5); ctx.lineTo(6.5, 4.5); ctx.lineTo(13.5, 4.5);
            ctx.lineTo(13.5, 11.5); ctx.lineTo(11.5, 11.5); ctx.stroke();
            break;
        case "close":
            ctx.beginPath();
            ctx.moveTo(4.5, 4.5); ctx.lineTo(13.5, 13.5);
            ctx.moveTo(13.5, 4.5); ctx.lineTo(4.5, 13.5);
            ctx.stroke();
            break;
        default:
            ctx.beginPath();
            ctx.arc(9, 9, 2, 0, Math.PI * 2);
            ctx.fill();
        }
    }
}
