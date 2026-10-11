// SPDX-License-Identifier: Apache-2.0
// HyprNova :: sparkline / area chart
//
// Hand-drawn with Canvas rather than QtCharts, for three reasons that all matter
// on a live dashboard:
//   * QtCharts is a separate module and a heavyweight dependency for one line.
//   * A Canvas repaint of 720 points costs well under a millisecond; a QtCharts
//     model reset re-lays-out axes and visibly stutters at 4 Hz.
//   * The gradient fill under the line, the glow on the leading edge and the
//     "now" marker are all things QtCharts would need a custom series for anyway.
//
// `series` is an array of numbers. `Canvas.requestPaint()` is driven by
// onSeriesChanged, so a refresh replaces the array wholesale and repaints once.

import QtQuick
import "../theme"

Item {
    id: root

    /// Array of numbers, oldest first.
    property var series: []
    property color lineColor: Theme.seriesA
    /// Fill under the line. Set alpha to 0 for a bare line.
    property bool fill: true
    /// Draw the horizontal grid lines.
    property bool grid: true
    /// Number of horizontal grid lines.
    property int gridLines: 3
    /// Upper bound. -1 => auto-scale to the data.
    property real maxValue: -1.0
    property real minValue: 0.0
    /// Label for the leading (newest) value.
    property string unit: ""
    /// Show the "now" dot at the right edge.
    property bool showHead: true
    /// Stroke width.
    property real lineWidth: 1.8

    implicitHeight: 64
    implicitWidth: 240

    readonly property real resolvedMax: {
        if (root.maxValue >= 0) return root.maxValue;
        var m = root.minValue;
        for (var i = 0; i < root.series.length; ++i)
            m = Math.max(m, Number(root.series[i]) || 0);
        // Pad by 15% so the peak is not glued to the top edge, and never return 0
        // (which would divide by zero in the mapper).
        return m <= 0 ? 1.0 : m * 1.15;
    }

    readonly property real headValue: root.series.length > 0
                                      ? Number(root.series[root.series.length - 1]) || 0 : 0

    Canvas {
        id: canvas
        anchors.fill: parent
        // RenderTarget.FramebufferObject + no antialias on the fill gives a crisp
        // 1 px grid on HiDPI; the line itself is stroked with AA on.
        renderStrategy: Canvas.Cooperative
        antialiasing: true

        onPaint: {
            var ctx = getContext("2d");
            ctx.reset();
            var w = width, h = height;
            if (w <= 2 || h <= 2) return;

            var max = root.resolvedMax;
            var min = root.minValue;
            var span = (max - min) || 1;
            var n = root.series.length;

            // ---- grid ----
            if (root.grid && root.gridLines > 0) {
                ctx.lineWidth = 1;
                ctx.strokeStyle = Theme.gridLine;
                for (var g = 1; g <= root.gridLines; ++g) {
                    var gy = Math.round(h - (h * g / (root.gridLines + 1))) + 0.5;
                    ctx.beginPath();
                    ctx.moveTo(0, gy);
                    ctx.lineTo(w, gy);
                    ctx.stroke();
                }
            }

            if (n < 2) return;

            var stepX = w / (n - 1);
            // Inline mappers rather than nested functions: QML's JS engine accepts
            // them, but hoisting inside a signal handler is easy to get subtly
            // wrong and impossible to unit-test.
            var px = function(i) { return i * stepX; };
            var py = function(v) { return h - ((Number(v) || 0) - min) / span * h; };

            // ---- fill ----
            if (root.fill) {
                var grad = ctx.createLinearGradient(0, 0, 0, h);
                grad.addColorStop(0.0, Theme.withAlpha(root.lineColor, 0.32));
                grad.addColorStop(0.6, Theme.withAlpha(root.lineColor, 0.08));
                grad.addColorStop(1.0, Theme.withAlpha(root.lineColor, 0.0));
                ctx.beginPath();
                ctx.moveTo(px(0), h);
                for (var i = 0; i < n; ++i) ctx.lineTo(px(i), py(root.series[i]));
                ctx.lineTo(px(n - 1), h);
                ctx.closePath();
                ctx.fillStyle = grad;
                ctx.fill();
            }

            // ---- line ----
            ctx.beginPath();
            ctx.moveTo(px(0), py(root.series[0]));
            for (var j = 1; j < n; ++j) ctx.lineTo(px(j), py(root.series[j]));
            ctx.lineWidth = root.lineWidth;
            ctx.lineJoin = "round";
            ctx.lineCap = "round";
            ctx.strokeStyle = String(root.lineColor);
            ctx.stroke();

            // ---- head marker ----
            if (root.showHead) {
                var hx = px(n - 1), hy = py(root.series[n - 1]);
                ctx.beginPath();
                ctx.arc(hx - 2, hy, 4.5, 0, Math.PI * 2);
                ctx.fillStyle = Theme.withAlpha(root.lineColor, 0.25);
                ctx.fill();
                ctx.beginPath();
                ctx.arc(hx - 2, hy, 2.2, 0, Math.PI * 2);
                ctx.fillStyle = String(root.lineColor);
                ctx.fill();
            }
        }
    }

    onSeriesChanged: canvas.requestPaint()
    onWidthChanged: canvas.requestPaint()
    onHeightChanged: canvas.requestPaint()
    onLineColorChanged: canvas.requestPaint()
    onResolvedMaxChanged: canvas.requestPaint()

    // Newest value, pinned top-right. Small, mono, dim: the shape carries the
    // information, the number carries the precision.
    Text {
        anchors { right: parent.right; top: parent.top; margins: Theme.space1 }
        text: (Math.round(root.headValue * 10) / 10) + root.unit
        color: Theme.textDim
        font { pixelSize: Theme.fontSizeMicro; family: Theme.monoFamily }
        visible: root.showHead
    }
}
