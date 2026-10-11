// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 7 — hyprnova-gui, the Qt6/QML dashboard
//
// A SEPARATE PROCESS from the agent, deliberately:
//
//   * A crashing console must never take down detection.
//   * The console runs as the desktop user, unprivileged. Every privileged
//     operation goes through the agent's socket and is re-authorised there, so a
//     compromised GUI gets the agent's policy engine, not the agent's root.
//   * Restarting it is free: it reconnects and receives a full state snapshot.
//
// Startup order matters. The theme is registered as a singleton BEFORE the engine
// loads any QML, because QML singletons are resolved at parse time and a missing
// Theme produces a cascade of "Cannot assign to non-existent property" errors that
// look like a QML bug but are an ordering bug.

#include <QCoreApplication>
#include <QGuiApplication>
#include <QIcon>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>
#include <QQuickWindow>
#include <QCommandLineParser>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSGRendererInterface>
#include <QString>
#include <QUrl>

#include <cstdio>
#include <string>

#include "core/config.hpp"
#include "core/log.hpp"
#include "gui/backend.hpp"

namespace {

/// Locate the QML entry point. Three candidates, in the order that makes
/// development, an installed package, and an AppImage all work:
///   1. next to the binary            (build tree / AppImage)
///   2. the compiled-in resource      (qrc, when built with gui/qml/qml.qrc)
///   3. the installed share directory (/usr/share/hyprnova/qml)
[[nodiscard]] QUrl resolve_main_qml(const QString& override_path) {
    if (!override_path.isEmpty()) {
        const QFileInfo fi{override_path};
        if (fi.exists()) return QUrl::fromLocalFile(fi.absoluteFilePath());
        std::fprintf(stderr, "hyprnova-gui: --qml '%s' does not exist\n",
                     override_path.toStdString().c_str());
    }
    const QString beside =
        QCoreApplication::applicationDirPath() + QStringLiteral("/qml/main.qml");
    if (QFile::exists(beside)) return QUrl::fromLocalFile(beside);

    const QUrl qrc{QStringLiteral("qrc:/qml/main.qml")};
    if (QFile::exists(QStringLiteral(":/qml/main.qml"))) return qrc;

    for (const QString& dir : {QStringLiteral("/usr/share/hyprnova/qml"),
                               QStringLiteral("/usr/local/share/hyprnova/qml")}) {
        const QString candidate = dir + QStringLiteral("/main.qml");
        if (QFile::exists(candidate)) return QUrl::fromLocalFile(candidate);
    }
    return {};
}

}  // namespace

int main(int argc, char* argv[]) {
    // The scene graph renders on its own thread by default, which is what keeps
    // the UI smooth while the backend marshals event bursts. Set it before
    // QGuiApplication exists, because afterwards it is ignored.
    QQuickWindow::setGraphicsApi(QSGRendererInterface::OpenGL);

    QGuiApplication app(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("HyprNova Anti-Malware Sec"));
    QCoreApplication::setApplicationVersion(QStringLiteral("1.0.0"));
    QCoreApplication::setOrganizationName(QStringLiteral("HyprNova"));

    QCommandLineParser parser;
    parser.setApplicationDescription(
        QStringLiteral("HyprNova Anti-Malware Sec console. Connects to the running agent (hyprnovad) "
                       "over its IPC socket; the agent remains authoritative for every action."));
    parser.addHelpOption();
    parser.addVersionOption();
    QCommandLineOption socket_opt{{"s", "socket"},
                                  QStringLiteral("Agent IPC socket (default: from /etc/hyprnova/agent.json)"),
                                  QStringLiteral("path")};
    QCommandLineOption config_opt{{"c", "config"}, QStringLiteral("Agent configuration to read GUI settings from"),
                                  QStringLiteral("path"), QStringLiteral("/etc/hyprnova/agent.json")};
    QCommandLineOption qml_opt{{"qml"}, QStringLiteral("Path to main.qml (development)"),
                               QStringLiteral("path")};
    QCommandLineOption theme_opt{{"theme"}, QStringLiteral("Theme name (midnight|carbon)"),
                                 QStringLiteral("name")};
    QCommandLineOption hz_opt{{"hz"}, QStringLiteral("Refresh rate in Hz, 1-10 (default from config)"),
                              QStringLiteral("n")};
    parser.addOption(socket_opt);
    parser.addOption(config_opt);
    parser.addOption(qml_opt);
    parser.addOption(theme_opt);
    parser.addOption(hz_opt);
    parser.process(app);

    // ---- configuration ----
    // Read the agent's config for the socket path and refresh rate so one file
    // describes the deployment. Failing to read it is not fatal: the defaults are
    // the same ones the agent uses.
    std::string socket_path = "/run/hyprnova/gui.sock";
    std::string theme_name = "midnight";
    int refresh_hz = 4;
    bool show_kernel_events = false;
    bool vibrancy_on = true;
    {
        const std::string cfg_path = parser.value(config_opt).toStdString();
        std::vector<hyprnova::core::ConfigError> errs;
        if (auto cfg = hyprnova::core::load_config(cfg_path, &errs)) {
            socket_path = cfg->gui.ipc_socket;
            theme_name = cfg->gui.theme;
            refresh_hz = cfg->gui.telemetry_hz;
            show_kernel_events = cfg->gui.show_kernel_events;
            vibrancy_on = cfg->gui.vibrancy;
        } else {
            std::fprintf(stderr,
                         "hyprnova-gui: could not read %s (%s); using built-in defaults\n",
                         cfg_path.c_str(), errs.empty() ? "unreadable" : errs.front().message.c_str());
        }
    }
    if (parser.isSet(socket_opt)) socket_path = parser.value(socket_opt).toStdString();
    if (parser.isSet(theme_opt)) theme_name = parser.value(theme_opt).toStdString();
    if (parser.isSet(hz_opt)) {
        bool ok_conv = false;
        const int v = parser.value(hz_opt).toInt(&ok_conv);
        if (ok_conv && v >= 1 && v <= 10) refresh_hz = v;
    }

    // ---- Qt Quick Controls style ----
    // Fusion is the only stock style that respects a custom palette completely.
    // The Basic/Material styles re-implement their own chrome and will fight the
    // dark theme.
    QQuickStyle::setStyle(QStringLiteral("Fusion"));

    // ---- backend ----
    hyprnova::gui::Backend backend;
    backend.start(QString::fromStdString(socket_path), refresh_hz);

    // ---- QML engine ----
    QQmlApplicationEngine engine;

    // The QML directory is added as an import path so `import "theme"` and the
    // Theme singleton resolve whether we run from the build tree or installed.
    const QUrl main_qml = resolve_main_qml(parser.value(qml_opt));
    if (main_qml.isEmpty()) {
        std::fprintf(stderr,
                     "hyprnova-gui: cannot find main.qml. Looked beside the binary and in "
                     "/usr/share/hyprnova/qml. Pass --qml /path/to/main.qml.\n");
        return 1;
    }
    if (main_qml.isLocalFile()) {
        engine.addImportPath(QFileInfo(main_qml.toLocalFile()).absolutePath());
    }

    // Context properties rather than qmlRegisterType: there is exactly one backend
    // per console, it outlives every QML object, and a context property avoids
    // QML constructing a second one (which would open a second socket).
    QQmlContext* ctx = engine.rootContext();
    ctx->setContextProperty(QStringLiteral("backend"), &backend);
    ctx->setContextProperty(QStringLiteral("agentSocket"), QString::fromStdString(socket_path));
    ctx->setContextProperty(QStringLiteral("themeName"), QString::fromStdString(theme_name));
    ctx->setContextProperty(QStringLiteral("refreshHz"), refresh_hz);
    ctx->setContextProperty(QStringLiteral("showKernelEvents"), show_kernel_events);
    ctx->setContextProperty(QStringLiteral("guiVersion"), QCoreApplication::applicationVersion());
    ctx->setContextProperty(QStringLiteral("windowVibrancy"), vibrancy_on);

    // Fail loudly rather than showing a blank window: objectCreationFailed means a
    // QML syntax error or a missing import, and the console output is the only
    // place that says which.
    QObject::connect(&engine, &QQmlApplicationEngine::objectCreationFailed, &app,
                     []() {
                         std::fprintf(stderr, "hyprnova-gui: QML failed to load; see the messages above\n");
                         QCoreApplication::exit(1);
                     },
                     Qt::QueuedConnection);

    engine.load(main_qml);
    if (engine.rootObjects().isEmpty()) return 1;

    const int rc = QGuiApplication::exec();
    backend.shutdown();
    return rc;
}
