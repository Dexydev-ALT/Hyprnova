// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 7 — theme singleton
//
// One source of truth for every colour, font size, spacing unit and radius in the
// console. QML that hard-codes "#ff3355" in a page cannot be re-themed, and an EDR
// console gets white-labelled; so nothing outside this file names a colour.
//
// Design intent, in the order it matters:
//   1. DARK, and dark for a reason: this runs on a wall monitor and on a laptop at
//      3 a.m. A white background in a NOC is a hazard.
//   2. SEVERITY IS THE ONLY SATURATED THING ON SCREEN. Chrome is desaturated blue-
//      grey; colour is reserved for meaning. If everything glows, nothing does.
//   3. GLOW == ATTENTION. A halo is drawn only for Critical/High, so the eye is
//      trained to treat a glow as "look here now".
//   4. TYPE IS TABBULAR. Counts and pids use monospace digits so columns do not
//      jitter when a value changes — jitter on a live-updating table is unreadable.

pragma Singleton
import QtQuick

QtObject {
    id: theme

    // ---- named palette -----------------------------------------------------
    // Base surfaces, darkest to lightest. Modelled on the reference look: a deep
    // near-black content plane, a LIGHTER grey sidebar (the reverse of the usual
    // rail), opaque cards, and one saturated green used for "healthy" actions.
    // Each step is ~4% lighter, which is the smallest delta that reads as a
    // separate plane on an IPS panel without looking striped.
    readonly property color voidBlack:   "#070A0F"   // behind everything, letterbox
    readonly property color bg:          "#10141B"   // content plane (opaque)
    readonly property color surface:     "#1A2028"   // sidebar, cards and panels
    readonly property color surfaceAlt:  "#222933"   // table header, hover, active pill
    readonly property color raised:      "#29323E"   // dialogs, popovers
    readonly property color border:      "#272F3A"   // hairline separators
    readonly property color borderSoft:  "#1E252F"   // inner borders

    // Vibrancy: the base plate the whole shell sits on. Semi-transparent so a
    // compositor shows the desktop through it; every ELEMENT drawn on top is
    // fully opaque (cards, text, controls never are -- blur under text is
    // unreadable). If the window manager has no compositor the alpha is simply
    // ignored by Qt and the shell renders opaque: same look, no artifacts.
    readonly property real   baseAlpha:  0.90
    readonly property color base:        Qt.rgba(0.051, 0.066, 0.090, baseAlpha)
    readonly property int   windowRadius: 14

    // Recommendation / hero accents. The two-card gradient pair and the hero
    // blob colour are drawn on Canvas (no graphical-effects import needed).
    readonly property color heroGlow:    "#12B995"   // radial blob behind the shield
    readonly property color recCardA:    "#2D6BDD"   // recommendation gradient start
    readonly property color recCardB:    "#7A4FD6"   // recommendation gradient end
    readonly property color searchBg:    "#141920"

    // Text, brightest to dimmest. Never pure white on near-black: the halation
    // makes long reading sessions painful.
    readonly property color text:        "#F2F5F9"
    readonly property color textDim:     "#9AA6B6"
    readonly property color textFaint:   "#5F6B7C"
    readonly property color textOnAccent:"#FFFFFF"

    // Brand accent: the reference product's green. Reads as "healthy/protected",
    // and stays the ONLY saturated chrome colour on the shell.
    readonly property color accent:      "#1EC8A5"
    readonly property color accentDim:   "#128268"
    readonly property color accentGlow:  "#331EC8A5"   // 20% alpha, for halos

    // ---- severity ramp -----------------------------------------------------
    // Five steps, monotonic in both hue warmth and luminance, so severity is
    // legible to a colour-blind operator AND in a greyscale screenshot.
    readonly property color info:        "#3E8FD8"
    readonly property color low:         "#37C7A4"
    readonly property color medium:      "#E8C341"
    readonly property color high:        "#F5883C"
    readonly property color critical:    "#FF3B5C"
    readonly property color ok:          "#2BE08A"
    readonly property color degraded:    "#E8C341"
    readonly property color down:        "#FF3B5C"

    // ---- chart series ------------------------------------------------------
    readonly property color seriesA:     "#1EC8A5"
    readonly property color seriesB:     "#8E7CFF"
    readonly property color seriesC:     "#37C7A4"
    readonly property color seriesD:     "#F5883C"
    readonly property color gridLine:    "#16202F"

    // ---- typography --------------------------------------------------------
    readonly property string fontFamily:    "Inter"
    readonly property string fontFallback:  "Segoe UI"
    readonly property string monoFamily:    "JetBrains Mono"
    readonly property string monoFallback:  "Consolas"

    readonly property int fontSizeMicro:  10
    readonly property int fontSizeSmall:  11
    readonly property int fontSizeBody:   13
    readonly property int fontSizeLarge:  15
    readonly property int fontSizeTitle:  19
    readonly property int fontSizeHero:   44   // the posture number

    readonly property int weightRegular:  Font.Normal
    readonly property int weightMedium:   Font.Medium
    readonly property int weightBold:     Font.DemiBold

    // ---- geometry ----------------------------------------------------------
    readonly property int space1: 4
    readonly property int space2: 8
    readonly property int space3: 12
    readonly property int space4: 16
    readonly property int space5: 24
    readonly property int space6: 32

    readonly property int radiusSm: 4
    readonly property int radiusMd: 8
    readonly property int radiusLg: 14
    readonly property int radiusPill: 999

    readonly property int sidebarWidth: 216
    readonly property int topbarHeight: 60
    readonly property int statusbarHeight: 28
    readonly property int rowHeight: 34
    readonly property int cardMinWidth: 280

    // ---- motion ------------------------------------------------------------
    // Fast enough to feel instant, slow enough to be perceived. Anything over
    // ~220 ms on a dashboard reads as lag.
    readonly property int animFast: 90
    readonly property int animNormal: 160
    readonly property int animSlow: 260
    readonly property int pulseMs: 1800

    // ---- helpers -----------------------------------------------------------
    /// Map the agent's severity string onto a colour. The single most-called
    /// function in the console; a switch keeps it allocation-free.
    function severityColor(severity) {
        switch (String(severity).toLowerCase()) {
        case "critical": return critical;
        case "high":     return high;
        case "medium":   return medium;
        case "low":      return low;
        case "info":     return info;
        default:         return textFaint;
        }
    }

    function sensorStateColor(state) {
        switch (String(state).toLowerCase()) {
        case "running":  return ok;
        case "degraded": return degraded;
        case "failed":   return down;
        case "starting": return accent;
        case "stopping": return textFaint;
        default:         return textFaint;
        }
    }

    function verdictColor(verdict) {
        switch (String(verdict).toLowerCase()) {
        case "malicious":  return critical;
        case "suspicious": return high;
        case "unknown":    return medium;
        case "error":      return down;
        case "skipped":    return textFaint;
        default:           return ok;
        }
    }

    /// Risk 0..1000 -> colour. Interpolated rather than bucketed so the live risk
    /// table shows movement, not just threshold crossings.
    function riskColor(risk) {
        var r = Math.max(0, Math.min(1000, Number(risk) || 0)) / 1000.0;
        if (r < 0.35) return Qt.rgba(low.r, low.g, low.b, 1.0);
        if (r < 0.60) return Qt.rgba(medium.r, medium.g, medium.b, 1.0);
        if (r < 0.80) return Qt.rgba(high.r, high.g, high.b, 1.0);
        return Qt.rgba(critical.r, critical.g, critical.b, 1.0);
    }

    /// True when a severity deserves a glow. Deliberately restrictive: if every
    /// row glows, the operator learns to ignore all of them.
    function shouldGlow(severity) {
        var s = String(severity).toLowerCase();
        return s === "critical" || s === "high";
    }

    /// 0xRRGGBB -> "#AARRGGBB" with the given alpha, for halos and fills derived
    /// from a severity colour.
    function withAlpha(c, a) {
        return Qt.rgba(c.r, c.g, c.b, a);
    }

    function formatUptime(seconds) {
        var s = Math.max(0, Math.floor(Number(seconds) || 0));
        var d = Math.floor(s / 86400); s -= d * 86400;
        var h = Math.floor(s / 3600);  s -= h * 3600;
        var m = Math.floor(s / 60);    s -= m * 60;
        if (d > 0) return d + "d " + h + "h";
        if (h > 0) return h + "h " + m + "m";
        if (m > 0) return m + "m " + s + "s";
        return s + "s";
    }

    function formatBytes(n) {
        var v = Number(n) || 0;
        var units = ["B", "KiB", "MiB", "GiB", "TiB"];
        var i = 0;
        while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
        return (i === 0 ? v : v.toFixed(1)) + " " + units[i];
    }

    /// Epoch seconds -> "HH:mm:ss" in local time. The feed is read as a timeline,
    /// so time-of-day beats relative "3s ago" for correlating with other logs.
    function formatClock(epochSeconds) {
        var d = new Date(Number(epochSeconds) * 1000);
        return Qt.formatTime(d, "HH:mm:ss");
    }

    function formatDate(epochSeconds) {
        var d = new Date(Number(epochSeconds) * 1000);
        return Qt.formatDateTime(d, "yyyy-MM-dd HH:mm:ss");
    }

    /// Truncate with an ellipsis in the MIDDLE, keeping both ends: for paths, the
    /// filename and the top-level directory are the informative parts.
    function elideMiddle(text, maxChars) {
        var t = String(text === undefined || text === null ? "" : text);
        var m = Math.max(8, maxChars || 48);
        if (t.length <= m) return t;
        var head = Math.ceil((m - 1) * 0.45);
        var tail = m - 1 - head;
        return t.substring(0, head) + "\u2026" + t.substring(t.length - tail);
    }

    /// Basename of a path, for the compact columns.
    function baseName(path) {
        var t = String(path === undefined || path === null ? "" : path);
        var i = t.lastIndexOf("/");
        return i >= 0 && i < t.length - 1 ? t.substring(i + 1) : t;
    }
}
