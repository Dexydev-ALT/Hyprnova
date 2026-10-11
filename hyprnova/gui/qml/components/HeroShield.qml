// SPDX-License-Identifier: Apache-2.0
// HyprNova :: HeroShield -- the big "protected" blob with shield + check mark.
//
// The reference app's hero is a soft green radial glow behind a rounded shield.
// Both layers are painted here: the glow as a radial gradient on a Canvas, the
// shield as filled bezier shapes -- no image assets, no graphical-effects import,
// nothing that can silently miss on a slim Qt install.
//
// `ok` picks the mood: green for protected, amber for warnings, red when the
// posture says the operator must act.

import QtQuick

Item {
    id: hero

    property bool ok: true
    property string mood: "ok"   // "ok" | "warn" | "bad" (mood wins when set)
    property color glowColor: mood === "bad" ? "#C93B54" : mood === "warn" ? "#C9A23B" : "#12B995"

    implicitWidth: 300
    implicitHeight: 260

    Canvas {
        id: glow
        anchors { fill: parent; topMargin: 10; bottomMargin: 26; leftMargin: 10; rightMargin: 10 }
        renderStrategy: Canvas.Immediate
        onPaint: {
            var ctx = getContext("2d");
            ctx.reset();
            var cx = width / 2, cy = height / 2;
            var grad = ctx.createRadialGradient(cx, cy, 6, cx, cy, Math.min(cx, cy));
            var c = Qt.rgba(hero.glowColor.r, hero.glowColor.g, hero.glowColor.b, 0.85);
            var c0 = Qt.rgba(hero.glowColor.r, hero.glowColor.g, hero.glowColor.b, 0.0);
            grad.addColorStop(0, c);
            grad.addColorStop(0.55, Qt.rgba(hero.glowColor.r, hero.glowColor.g, hero.glowColor.b, 0.35));
            grad.addColorStop(1, c0);
            ctx.fillStyle = grad;
            // a slightly irregular blob, like the reference, not a perfect circle
            ctx.beginPath();
            var pts = [[0.5,0.02],[0.86,0.16],[0.98,0.52],[0.82,0.9],[0.5,1.0],[0.16,0.88],[0.02,0.5],[0.15,0.14]];
            for (var i = 0; i < pts.length; i++) {
                var x = pts[i][0] * width, y = pts[i][1] * height;
                if (i === 0) ctx.moveTo(x, y);
                else {
                    var px = pts[i-1][0] * width, py = pts[i-1][1] * height;
                    ctx.quadraticCurveTo((px + x) / 2, (py + y) / 2, x, y);
                }
            }
            ctx.closePath();
            ctx.fill();
        }
    }

    Canvas {
        id: shield
        anchors.centerIn: parent
        width: 120; height: 132
        renderStrategy: Canvas.Immediate
        onPaint: {
            var ctx = getContext("2d");
            ctx.reset();
            var w = width, h = height;

            // shield body: white by day, near-white here -- the reference uses a
            // light shield on the green blob with a dark check.
            ctx.beginPath();
            ctx.moveTo(w * 0.5, h * 0.02);
            ctx.bezierCurveTo(w * 0.72, h * 0.10, w * 0.88, h * 0.14, w * 0.93, h * 0.16);
            ctx.bezierCurveTo(w * 0.95, h * 0.40, w * 0.92, h * 0.68, w * 0.5, h * 0.985);
            ctx.bezierCurveTo(w * 0.08, h * 0.68, w * 0.05, h * 0.40, w * 0.07, h * 0.16);
            ctx.bezierCurveTo(w * 0.12, h * 0.14, w * 0.28, h * 0.10, w * 0.5, h * 0.02);
            ctx.closePath();
            ctx.fillStyle = "#F4F8F6";
            ctx.fill();

            // subtle inner edge so the shield is not flat on bright glow
            ctx.lineWidth = 2;
            ctx.strokeStyle = "rgba(0,0,0,0.10)";
            ctx.stroke();

            // the check: dark green, thick, round caps
            ctx.beginPath();
            ctx.moveTo(w * 0.32, h * 0.50);
            ctx.lineTo(w * 0.455, h * 0.635);
            ctx.lineTo(w * 0.70, h * 0.335);
            ctx.lineWidth = 9;
            ctx.lineCap = "round";
            ctx.lineJoin = "round";
            ctx.strokeStyle = hero.mood === "bad" ? "#B33A50"
                            : hero.mood === "warn" ? "#8A6E1F" : "#0E7A5F";
            ctx.stroke();
        }
    }

    onMoodChanged: { glow.requestPaint(); shield.requestPaint(); }
    onGlowColorChanged: glow.requestPaint()
}
