// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 7 — Qt6 backend implementation
//
// Two objects, two threads:
//
//   Backend        lives on the main/GUI thread. Owns every value QML reads. Its
//                  only work is marshalling and signal emission.
//   BackendWorker  lives on worker_thread_. Owns the socket, the reconnect
//                  backoff, the send queue, the read buffer and QJsonDocument
//                  parsing. It never touches a QML-visible value directly.
//
// They communicate exclusively through queued connections, so nothing the daemon
// does -- a 4 MiB process table, a burst of 500 events/s, a socket that vanishes
// mid-frame -- can stall a repaint.

#include "gui/backend.hpp"

#include <QCoreApplication>
#include <QDateTime>
#include <QElapsedTimer>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QLocalSocket>
#include <QMetaObject>
#include <QThread>

#include <algorithm>
#include <chrono>
#include <utility>

namespace hyprnova::gui {

// ===========================================================================
// Worker
// ===========================================================================

class BackendWorker final : public QObject {
    Q_OBJECT
public:
    BackendWorker() = default;
    ~BackendWorker() override { close(); }

    BackendWorker(const BackendWorker&) = delete;
    BackendWorker& operator=(const BackendWorker&) = delete;

public slots:
    /// Runs on the worker thread. Creates the socket here so its QObject affinity
    /// is the worker thread -- creating it on the main thread and moving it would
    /// leave its internal notifier on the wrong event loop.
    void configure(const QString& path, int pollMs) {
        path_ = path;
        poll_ms_ = std::max(50, pollMs);
        if (!socket_) {
            socket_ = new QLocalSocket(this);
            connect(socket_, &QLocalSocket::connected, this, &BackendWorker::onConnected);
            connect(socket_, &QLocalSocket::readyRead, this, &BackendWorker::onReadyRead);
            connect(socket_, &QLocalSocket::disconnected, this, &BackendWorker::onDisconnected);
            connect(socket_, &QLocalSocket::errorOccurred, this, &BackendWorker::onError);
        }
        connect(&timer_, &QTimer::timeout, this, &BackendWorker::onTick);
        timer_.setInterval(poll_ms_);
        timer_.start();
        tryConnect();
    }

    void send(const QJsonObject& request) {
        if (!socket_ || socket_->state() != QLocalSocket::ConnectedState) {
            // Keep the last few requests so a reconnect does not silently swallow
            // the operator's click. Bounded: an operator mashing "refresh" while
            // the agent is down must not build an unbounded queue.
            if (pending_.size() < 16) pending_.append(request);
            return;
        }
        const QByteArray frame = QJsonDocument(request).toJson(QJsonDocument::Compact) + "\n";
        socket_->write(frame);
        socket_->flush();
    }

    void stop() {
        timer_.stop();
        close();
    }

signals:
    void connectionState(bool ok, QString error);
    void replyArrived(QString cmd, bool ok, QJsonObject data, QString error);
    void telemetryArrived(QJsonObject event);

private slots:
    void onTick() {
        if (!socket_ || socket_->state() == QLocalSocket::UnconnectedState) tryConnect();
        // Flush anything queued while we were disconnected.
        if (socket_ && socket_->state() == QLocalSocket::ConnectedState && !pending_.isEmpty()) {
            const auto queued = std::exchange(pending_, {});
            for (const auto& q : queued) send(q);
        }
    }

    void onConnected() {
        backoff_ms_ = kInitialBackoffMs;
        // Ask for everything at once: a console that connects mid-incident must
        // not show empty panels for the first few seconds.
        send({{"cmd", "ping"}});
        emit connectionState(true, QString());
        for (const char* cmd : {"overview", "sensors", "events", "risk", "decisions", "remediation",
                                "network", "processes", "scans", "hardening", "canaries", "baseline", "toolbox",
                                "settings_get", "mem_status"}) {
            send({{"cmd", QString::fromLatin1(cmd)}, {"limit", 200}});
        }
    }

    void onDisconnected() {
        emit connectionState(false, QStringLiteral("the agent closed the connection"));
        tryConnect();
    }

    void onError(QLocalSocket::LocalSocketError) {
        const QString why = socket_ ? socket_->errorString() : QStringLiteral("socket error");
        emit connectionState(false, why);
        tryConnect();
    }

    void onReadyRead() {
        rx_.append(socket_->readAll());
        if (rx_.size() > kMaxBuffer) {
            // A reply this large is a protocol violation or a runaway snapshot.
            // Drop the buffer rather than grow: the GUI is not allowed to become
            // an OOM vector, and reconnecting recovers cleanly.
            rx_.clear();
            close();
            tryConnect();
            return;
        }
        for (;;) {
            const int nl = rx_.indexOf('\n');
            if (nl < 0) break;
            const QByteArray line = rx_.left(nl);
            rx_.remove(0, nl + 1);
            if (line.trimmed().isEmpty()) continue;
            dispatch(line);
        }
    }

private:
    static constexpr int kMaxBuffer = 128 * 1024 * 1024;
    static constexpr int kInitialBackoffMs = 500;
    static constexpr int kMaxBackoffMs = 15000;

    void tryConnect() {
        if (!socket_) return;
        if (socket_->state() != QLocalSocket::UnconnectedState) return;
        if (cooldown_.isValid() && cooldown_.elapsed() < backoff_ms_) return;
        cooldown_.start();
        socket_->connectToServer(path_);
        if (!socket_->waitForConnected(1000)) {
            // Exponential backoff, forever. The agent may legitimately be down for
            // an upgrade; the console must keep trying without spinning.
            socket_->abort();
            backoff_ms_ = std::min(backoff_ms_ * 2, kMaxBackoffMs);
        }
    }

    void close() {
        if (!socket_) return;
        socket_->abort();
        socket_->close();
    }

    void dispatch(const QByteArray& line) {
        QJsonParseError pe {};
        const auto doc = QJsonDocument::fromJson(line, &pe);
        if (pe.error != QJsonParseError::NoError || !doc.isObject()) return;
        const QJsonObject root = doc.object();

        // Unsolicited push frames are {"event": "..."}; replies are {"cmd": ...}.
        if (root.contains("event")) {
            const QString kind = root.value("event").toString();
            if (kind == QLatin1String("agent.shutdown")) {
                emit connectionState(false, root.value("reason").toString());
                return;
            }
            if (kind == QLatin1String("telemetry")) {
                const QJsonObject data = root.value("data").toObject();
                emit telemetryArrived(data);
                // A decision prompt must reach the modal dialog even if the panel
                // refresh has not landed yet.
                if (data.value("kind").toString() == QLatin1String("gui.decision_required")) {
                    emit replyArrived(QStringLiteral("decisions.push"), true, data, QString());
                }
                return;
            }
            return;
        }

        const QString cmd = root.value("cmd").toString();
        const bool ok = root.value("ok").toBool(true);
        const QString err = root.value("error").toString();
        const QJsonValue data = root.value("data");
        emit replyArrived(cmd, ok, data.isObject() ? data.toObject() : QJsonObject{}, err);
    }

    QLocalSocket* socket_{nullptr};
    QTimer timer_;
    QString path_;
    int poll_ms_{250};
    int backoff_ms_{kInitialBackoffMs};
    QElapsedTimer cooldown_;
    QByteArray rx_;
    QList<QJsonObject> pending_;
};

// ===========================================================================
// Backend
// ===========================================================================

namespace {

[[nodiscard]] QVariantMap toVariantMap(const QJsonObject& o) {
    return o.toVariantMap();
}

}  // namespace

Backend::Backend(QObject* parent) : QObject(parent) {
    worker_ = std::make_unique<BackendWorker>();
    worker_->moveToThread(&worker_thread_);
    connect(&worker_thread_, &QThread::finished, worker_.get(), &QObject::deleteLater);

    // Worker -> main. Queued by construction (different thread affinity), which is
    // exactly what keeps parsing off the render thread.
    connect(worker_.get(), &BackendWorker::connectionState, this, &Backend::onConnected);
    connect(worker_.get(), &BackendWorker::telemetryArrived, this, &Backend::onTelemetry);
    connect(worker_.get(), &BackendWorker::replyArrived, this,
            [this](const QString& cmd, bool ok, const QJsonObject& data, const QString& error) {
                onReply(cmd, ok, toVariantMap(data), error);
            });

    // The refresh timer runs on the main thread and only posts requests; the
    // worker does the I/O. Rate comes from cfg.gui.telemetry_hz.
    connect(&poll_, &QTimer::timeout, this, [this] {
        if (!connected_) return;
        send({{"cmd", "overview"}});
        send({{"cmd", "risk"}});
        // Heavy panels refresh at half rate: a full process table is thousands of
        // /proc reads on the agent side and is not worth doing 4x/second.
        static int tick = 0;
        if (++tick % 2 == 0) {
            send({{"cmd", "events"}, {"limit", 200}});
            send({{"cmd", "network"}});
            send({{"cmd", "sensors"}});
        }
        if (tick % 8 == 0) {
            send({{"cmd", "processes"}, {"limit", 300}});
            send({{"cmd", "scans"}});
            send({{"cmd", "remediation"}});
            send({{"cmd", "decisions"}});
        }
    });
}

Backend::~Backend() { shutdown(); }

void Backend::start(const QString& socketPath, int refreshHz) {
    refresh_hz_ = std::clamp(refreshHz, 1, 10);   // never above 10: see GuiConfig
    worker_thread_.setObjectName(QStringLiteral("hyprnova-gui-ipc"));
    worker_thread_.start();
    const int poll_ms = 1000 / refresh_hz_;
    QMetaObject::invokeMethod(worker_.get(), "configure", Qt::QueuedConnection,
                              Q_ARG(QString, socketPath), Q_ARG(int, poll_ms));
    poll_.start(poll_ms * 4);   // panel refresh is slower than the event feed
}

void Backend::shutdown() {
    poll_.stop();
    if (worker_thread_.isRunning()) {
        QMetaObject::invokeMethod(worker_.get(), "stop", Qt::BlockingQueuedConnection);
        worker_thread_.quit();
        worker_thread_.wait(2000);
    }
}

void Backend::send(const QJsonObject& request) {
    QMetaObject::invokeMethod(worker_.get(), "send", Qt::QueuedConnection,
                              Q_ARG(QJsonObject, request));
}

void Backend::applyTelemetryRate() {
    // Coalesce bursts: if a repaint has not consumed the previous event yet, we
    // still accept it (QML reads a snapshot list, not a queue), but we cap how far
    // ahead of the render loop the feed can run.
    if (telemetry_pending_.load(std::memory_order_relaxed) > 64) return;
    telemetry_pending_.fetch_add(1, std::memory_order_relaxed);
}

// ---- refresh entry points ----
void Backend::refreshOverview() { send({{"cmd", "overview"}}); }
void Backend::refreshSensors() { send({{"cmd", "sensors"}}); }
void Backend::refreshEvents(int limit) { send({{"cmd", "events"}, {"limit", limit}}); }
void Backend::refreshRisk() { send({{"cmd", "risk"}}); }
void Backend::refreshDecisions() { send({{"cmd", "decisions"}}); }
void Backend::refreshRemediation() { send({{"cmd", "remediation"}}); }
void Backend::refreshNetwork() { send({{"cmd", "network"}}); }
void Backend::refreshProcesses(int limit) { send({{"cmd", "processes"}, {"limit", limit}}); }
void Backend::refreshScans() { send({{"cmd", "scans"}}); }
void Backend::refreshHardening() { send({{"cmd", "hardening"}}); }
void Backend::refreshToolbox() { send({{"cmd", "toolbox"}}); }
void Backend::deepScan(const QString& profile) { send({{"cmd", "combined_scan"}, {"profile", profile}}); }
void Backend::refreshCanaries() { send({{"cmd", "canaries"}}); }
void Backend::refreshBaseline() { send({{"cmd", "baseline"}}); }

void Backend::refreshSettings() { send({{"cmd", "settings_get"}}); }

void Backend::setFeature(const QString& key, bool on) {
    send({{"cmd", "settings_set"}, {"key", key}, {"value", on ? 1 : 0}});
}

void Backend::refreshMemStatus() { send({{"cmd", "mem_status"}}); }

void Backend::askAi(const QString& question) {
    if (question.trimmed().isEmpty()) return;
    send({{"cmd", "ai_ask"}, {"question", question.toStdString()}});
}

void Backend::reviewAi(qint64 pid) {
    if (pid <= 1) return;
    send({{"cmd", "ai_review"}, {"pid", pid}});
}

void Backend::runTool(const QString& name, const QVariantList& args) {
    if (name.trimmed().isEmpty()) return;
    QJsonArray a;
    for (const auto& v : args) a.append(v.toString());
    send({{"cmd", "tool_run"}, {"name", name.toStdString()}, {"args", a}});
}

void Backend::vtLookup(const QString& sha256) {
    if (sha256.trimmed().isEmpty()) return;
    send({{"cmd", "vt_lookup"}, {"hash", sha256.trimmed().toStdString()}});
}

void Backend::refreshSnapshots() { send({{"cmd", "snapshots"}}); }

void Backend::createSnapshot(const QString& reason) {
    send({{"cmd", "snapshot"}, {"reason", reason.toStdString()}});
}

void Backend::restoreShadow(const QString& id, const QString& to) {
    if (id.trimmed().isEmpty()) return;
    send({{"cmd", "restore_shadow"}, {"id", id.toStdString()}, {"to", to.toStdString()}});
}

void Backend::verifySnapshot(const QString& id) {
    if (id.trimmed().isEmpty()) return;
    send({{"cmd", "verify_snapshot"}, {"id", id.toStdString()}});
}

void Backend::inspectMemory(qint64 pid) {
    if (pid <= 1) return;
    send({{"cmd", "mem_inspect"}, {"pid", pid}});
}

void Backend::dumpMemory(qint64 pid) {
    if (pid <= 1) return;
    // Explicit operator intent: the confirm dialog in the UI sets the flag.
    send({{"cmd", "mem_dump"}, {"pid", pid}, {"confirm", 1}});
}

QVariantMap Backend::aiAnswer() const { QMutexLocker lk{&mu_}; return ai_answer_; }
QVariantMap Backend::toolResult() const { QMutexLocker lk{&mu_}; return tool_result_; }
QVariantList Backend::snapshots() const { QMutexLocker lk{&mu_}; return snapshots_; }
QVariantMap Backend::snapshotReply() const { QMutexLocker lk{&mu_}; return snapshot_reply_; }
QVariantMap Backend::memStatus() const { QMutexLocker lk{&mu_}; return mem_status_; }
QVariantMap Backend::memReport() const { QMutexLocker lk{&mu_}; return mem_report_; }

void Backend::advancedScan(const QString& path) {
    if (path.isEmpty()) return;
    send({{"cmd", "advanced_scan"}, {"path", path}});
}
void Backend::refreshAll() {
    refreshOverview();
    refreshSensors();
    refreshEvents(400);
    refreshRisk();
    refreshDecisions();
    refreshRemediation();
    refreshNetwork();
    refreshProcesses(300);
    refreshScans();
    refreshHardening();
    refreshCanaries();
    refreshBaseline();
}

// ---- actions ----
void Backend::answer(qint64 id, const QString& a) {
    send({{"cmd", "answer"}, {"id", static_cast<double>(id)}, {"answer", a}});
}
void Backend::investigate(qint64 pid) {
    send({{"cmd", "investigate"},
          {"pid", static_cast<double>(pid)},
          {"reason", QStringLiteral("operator investigation from the GUI")}});
}
void Backend::resume(qint64 pid) { send({{"cmd", "resume"}, {"pid", static_cast<double>(pid)}}); }
void Backend::suspend(qint64 pid) { send({{"cmd", "suspend"}, {"pid", static_cast<double>(pid)}}); }
void Backend::isolate(qint64 pid) { send({{"cmd", "isolate"}, {"pid", static_cast<double>(pid)}}); }
void Backend::release(qint64 pid) { send({{"cmd", "release"}, {"pid", static_cast<double>(pid)}}); }
void Backend::kill(qint64 pid) { send({{"cmd", "kill"}, {"pid", static_cast<double>(pid)}}); }
void Backend::dismiss(qint64 pid) { send({{"cmd", "dismiss"}, {"pid", static_cast<double>(pid)}}); }
void Backend::quarantine(const QString& path) { send({{"cmd", "quarantine"}, {"path", path}}); }
void Backend::restore(qint64 id, const QString& to) {
    send({{"cmd", "restore"}, {"id", static_cast<double>(id)}, {"to", to}});
}
void Backend::block(const QString& ip, int port, qint64 ttl) {
    send({{"cmd", "block"}, {"ip", ip}, {"port", port}, {"ttl_seconds", static_cast<double>(ttl)}});
}
void Backend::unblock(qint64 id) { send({{"cmd", "unblock"}, {"id", static_cast<double>(id)}}); }
void Backend::unblockExe(qint64 id) {
    send({{"cmd", "unblock-exe"}, {"id", static_cast<double>(id)}});
}
void Backend::blockExe(qint64 pid) { send({{"cmd", "block-exe"}, {"pid", static_cast<double>(pid)}}); }
void Backend::harden(const QString& key, const QString& value) {
    send({{"cmd", "harden"}, {"key", key}, {"value", value}});
}
void Backend::hardenAll() { send({{"cmd", "harden_apply_all"}}); }
void Backend::rescanHardening() { send({{"cmd", "rescan_hardening"}}); }
void Backend::scanPath(const QString& path) { send({{"cmd", "scan"}, {"path", path}}); }
void Backend::fullSweep() { send({{"cmd", "sweep"}}); }
void Backend::plantCanaries() { send({{"cmd", "plant_canaries"}}); }
void Backend::reloadConfig() { send({{"cmd", "reload"}}); }
void Backend::runSelfTest() { send({{"cmd", "selftest"}}); }

QVariantList Backend::childrenOf(qint64 pid) const {
    QMutexLocker lk{&mu_};
    QVariantList out;
    for (const auto& v : processes_) {
        const auto m = v.toMap();
        if (m.value("ppid").toLongLong() == pid) out.append(m);
    }
    return out;
}

QVariantList Backend::lineageOf(qint64 pid) const {
    QMutexLocker lk{&mu_};
    // Walk parents from the cached snapshot. Bounded so a pid loop in a corrupted
    // /proc cannot make the GUI spin.
    QVariantList chain;
    qint64 cur = pid;
    for (int depth = 0; depth < 16 && cur > 0; ++depth) {
        const auto it = std::find_if(processes_.begin(), processes_.end(),
                                     [cur](const QVariant& v) {
                                         return v.toMap().value("pid").toLongLong() == cur;
                                     });
        if (it == processes_.end()) break;
        const auto m = it->toMap();
        chain.prepend(m);
        const qint64 parent = m.value("ppid").toLongLong();
        if (parent == cur) break;
        cur = parent;
    }
    return chain;
}

// ---- worker -> main slots ----
void Backend::onConnected(bool ok, QString error) {
    {
        QMutexLocker lk{&mu_};
        if (connected_ == ok && connection_error_ == error) return;
        connected_ = ok;
        connection_error_ = std::move(error);
    }
    emit connectedChanged();
    emit connectionErrorChanged();
    if (!connected_) emit notice(QStringLiteral("high"), connectionError());
}

void Backend::onOverview(QVariantMap data) {
    {
        QMutexLocker lk{&mu_};
        overview_ = std::move(data);
        posture_score_ = overview_.value("posture_score").toInt();
        posture_label_ = overview_.value("posture_label").toString();
        version_ = overview_.value("version").toString();
        uptime_ = overview_.value("uptime").toLongLong();
        published_ = overview_.value("published").toLongLong();
        dropped_ = overview_.value("dropped").toLongLong();
        sensors_running_ = overview_.value("sensors").toInt();
        sensors_degraded_ = overview_.value("degraded").toInt();
        pending_decisions_ = overview_.value("pending_decisions").toInt();
        active_blocks_ = overview_.value("active_blocks").toInt();
        suspended_pids_ = overview_.value("suspended").toInt();
        gui_clients_ = overview_.value("gui_clients").toLongLong();
        gui_frames_ = overview_.value("gui_frames").toLongLong();
        dry_run_ = overview_.value("dry_run").toBool();
        auto_respond_ = overview_.value("auto_respond").toBool();
        learning_ = overview_.value("learning").toBool();
        // learning_progress_ is owned by onBaseline(): the overview only carries a
        // coarse boolean, and guessing a fraction here would fight the real value.
        capabilities_ = overview_.value("capabilities").toMap();
        capability_notes_ = capabilities_.value("notes").toList();

        // Rolling series for the posture graph: one sample per overview, capped so
        // a console left open for a week does not grow without bound.
        QVariantMap point;
        point["t"] = QDateTime::currentSecsSinceEpoch();
        point["posture"] = posture_score_;
        point["events"] = published_;
        point["dropped"] = dropped_;
        point["risk"] = risk_summary_.value("top_score").toDouble();
        history_series_.append(point);
        while (history_series_.size() > 720) history_series_.removeFirst();
    }
    emit overviewChanged();
    emit historySeriesChanged();
}

void Backend::onEvents(QVariantList data) {
    {
        QMutexLocker lk{&mu_};
        // Newest first, and merge rather than replace so a refresh does not blank
        // the feed for the 200 ms the round trip takes.
        for (const auto& ev : data) {
            const auto id = ev.toMap().value("id").toLongLong();
            const bool known = std::any_of(events_.begin(), events_.end(),
                                           [id](const QVariant& v) {
                                               return v.toMap().value("id").toLongLong() == id;
                                           });
            if (!known) events_.prepend(ev);
        }
        while (events_.size() > 2000) events_.removeLast();
        telemetry_pending_.store(0, std::memory_order_relaxed);
    }
    emit eventsChanged();
}

void Backend::onTelemetry(QVariantMap event) {
    applyTelemetryRate();
    {
        QMutexLocker lk{&mu_};
        const auto id = event.value("id").toLongLong();
        const bool known = std::any_of(events_.begin(), events_.end(),
                                       [id](const QVariant& v) {
                                           return v.toMap().value("id").toLongLong() == id;
                                       });
        if (!known) events_.prepend(event);
        while (events_.size() > 2000) events_.removeLast();
    }
    emit eventsChanged();

    const QString kind = event.value("kind").toString();
    const QString sev = event.value("severity").toString();
    if (kind == QLatin1String("remediation.applied")) {
        emit actionCompleted(event);
    } else if (sev == QLatin1String("critical") || sev == QLatin1String("high")) {
        emit notice(sev, event.value("message").toString());
    }
}

void Backend::onSensors(QVariantList data) {
    {
        QMutexLocker lk{&mu_};
        sensors_ = std::move(data);
    }
    emit sensorsChanged();
}

void Backend::onRisk(QVariantMap data) {
    {
        QMutexLocker lk{&mu_};
        risk_actors_ = data.value("actors").toList();
        risk_summary_ = data;
        // Surface the highest score so the overview sparkline has something to
        // plot without a second round trip.
        double top = 0.0;
        for (const auto& a : risk_actors_) top = std::max(top, a.toMap().value("score").toDouble());
        risk_summary_["top_score"] = top;
    }
    emit riskChanged();
}

void Backend::onDecisions(QVariantList data) {
    const bool had_none = decisions_.isEmpty();
    {
        QMutexLocker lk{&mu_};
        decisions_ = std::move(data);
        pending_decisions_ = decisions_.size();
    }
    emit decisionsChanged();
    emit overviewChanged();
    // Interrupt the operator exactly once per new prompt, not once per refresh.
    if (!decisions_.isEmpty() && had_none) emit decisionRequired(decisions_.first().toMap());
}

void Backend::onRemediation(QVariantMap data) {
    {
        QMutexLocker lk{&mu_};
        actions_ = data.value("actions").toList();
        blocks_ = data.value("blocks").toList();
        quarantined_ = data.value("quarantine").toList();
        active_blocks_ = blocks_.size();
        suspended_pids_ = data.value("suspended_pids").toList().size();
    }
    emit remediationChanged();
}

void Backend::onNetwork(QVariantMap data) {
    {
        QMutexLocker lk{&mu_};
        listeners_ = data.value("listeners").toList();
        connections_ = data.value("connections").toList();
        beacons_ = data.value("beacons").toList();
        exe_blocks_ = data.value("exe_blocks").toList();
    }
    emit networkChanged();
}

void Backend::onProcesses(QVariantList data) {
    {
        QMutexLocker lk{&mu_};
        processes_ = std::move(data);
    }
    emit processesChanged();
}

void Backend::onScans(QVariantMap data) {
    {
        QMutexLocker lk{&mu_};
        scan_results_ = data.value("recent").toList();
        scan_counters_ = data.value("counters").toMap();
    }
    emit scansChanged();
}

void Backend::onHardening(QVariantMap data) {
    {
        QMutexLocker lk{&mu_};
        hardening_ = std::move(data);
    }
    emit hardeningChanged();
}

void Backend::onToolbox(QVariantMap data) {
    {
        QMutexLocker lk{&mu_};
        toolbox_ = std::move(data);
    }
    emit toolboxChanged();
}

void Backend::onCanaries(QVariantMap data) {
    {
        QMutexLocker lk{&mu_};
        canaries_ = std::move(data);
    }
    emit canariesChanged();
}

void Backend::onBaseline(QVariantMap data) {
    {
        QMutexLocker lk{&mu_};
        baseline_ = std::move(data);
        learning_ = baseline_.value("learning").toBool();
        const auto started = baseline_.value("started").toLongLong();
        const auto ends = baseline_.value("ends").toLongLong();
        const auto now = QDateTime::currentSecsSinceEpoch();
        learning_progress_ = ends > started
                                 ? std::clamp<double>(double(now - started) / double(ends - started), 0.0, 1.0)
                                 : (learning_ ? 0.0 : 1.0);
    }
    emit baselineChanged();
    emit overviewChanged();
}

QVariantMap Backend::settingsRaw() const { QMutexLocker lk{&mu_}; return settings_raw_; }

void Backend::onSettings(QVariantMap data) {
    {
        QMutexLocker lk{&mu_};
        settings_raw_ = data;
    }
    emit settingsRawChanged();
    QVariantList list;
    const QVariantMap states = data.value("states").toMap();
    const QVariantMap descs = data.value("descriptions").toMap();
    QStringList keys = states.keys();
    keys.sort();
    for (const QString& k : keys)
        list.append(QVariantMap{{"key", k},
                                {"on", states.value(k).toBool()},
                                {"description", descs.value(k).toString()}});
    {
        QMutexLocker lk{&mu_};
        feature_settings_ = std::move(list);
    }
    emit featureSettingsChanged();
}

void Backend::onReply(QString cmd, bool ok, QVariantMap data, QString error) {
    if (!ok) {
        emit notice(QStringLiteral("high"), error.isEmpty() ? cmd + QStringLiteral(" failed") : error);
        return;
    }
    if (cmd == QLatin1String("overview")) return onOverview(std::move(data));
    if (cmd == QLatin1String("sensors")) return onSensors(data.value("sensors").toList());
    if (cmd == QLatin1String("events")) return onEvents(data.value("events").toList());
    if (cmd == QLatin1String("risk")) return onRisk(std::move(data));
    if (cmd == QLatin1String("decisions")) return onDecisions(data.value("decisions").toList());
    if (cmd == QLatin1String("remediation")) return onRemediation(std::move(data));
    if (cmd == QLatin1String("network")) return onNetwork(std::move(data));
    if (cmd == QLatin1String("processes")) return onProcesses(data.value("processes").toList());
    if (cmd == QLatin1String("scans")) return onScans(std::move(data));
    if (cmd == QLatin1String("hardening")) return onHardening(std::move(data));
    if (cmd == QLatin1String("toolbox")) return onToolbox(std::move(data));
    if (cmd == QLatin1String("combined_scan")) {
        const QString verdict = data.value("verdict").toString();
        const QString severity =
            verdict == QLatin1String("INFECTED") ? QStringLiteral("critical")
          : verdict == QLatin1String("suspicious") ? QStringLiteral("high")
          : QStringLiteral("low");
        emit notice(severity, data.value("summary").toString());
        return;
    }
    if (cmd == QLatin1String("canaries")) return onCanaries(std::move(data));
    if (cmd == QLatin1String("baseline")) return onBaseline(std::move(data));
    if (cmd == QLatin1String("settings_get")) return onSettings(std::move(data));
    if (cmd == QLatin1String("settings_set")) {
        // The daemon already validated, applied and persisted; mirror its state.
        emit notice(QStringLiteral("info"),
                    QStringLiteral("%1 is now %2")
                        .arg(data.value("key").toString(),
                             data.value("value").toBool() ? QStringLiteral("ON")
                                                          : QStringLiteral("OFF")));
        send({{"cmd", "settings_get"}});
        return;
    }
    if (cmd == QLatin1String("mem_status")) {
        {
            QMutexLocker lk{&mu_};
            mem_status_ = std::move(data);
        }
        emit memStatusChanged();
        return;
    }
    if (cmd == QLatin1String("mem_inspect")) {
        {
            QMutexLocker lk{&mu_};
            mem_report_ = std::move(data);
        }
        emit memReportChanged();
        emit notice(data.value("suspicious").toBool() ? QStringLiteral("critical")
                                                      : QStringLiteral("low"),
                    QStringLiteral("memory inspection of pid %1: %2")
                        .arg(data.value("pid").toString())
                        .arg(data.value("suspicious").toBool()
                                 ? QStringLiteral("SUSPICIOUS (W^X or signature hit)")
                                 : QStringLiteral("no memory indicators")));
        return;
    }
    if (cmd == QLatin1String("ai_ask") || cmd == QLatin1String("ai_review")) {
        {
            QMutexLocker lk{&mu_};
            ai_answer_ = std::move(data);
        }
        emit aiAnswerChanged();
        return;
    }
    if (cmd == QLatin1String("tool_run") || cmd == QLatin1String("vt_lookup")) {
        {
            QMutexLocker lk{&mu_};
            tool_result_ = std::move(data);
        }
        emit toolResultChanged();
        return;
    }
    if (cmd == QLatin1String("snapshots")) {
        {
            QMutexLocker lk{&mu_};
            snapshots_ = data.value("data").toList();
        }
        emit snapshotsChanged();
        return;
    }
    if (cmd == QLatin1String("snapshot") || cmd == QLatin1String("restore_shadow") ||
        cmd == QLatin1String("verify_snapshot")) {
        {
            QMutexLocker lk{&mu_};
            snapshot_reply_ = std::move(data);
        }
        emit snapshotReplyChanged();
        refreshSnapshots();  // the list may have changed; keep it truthful
        return;
    }
    if (cmd == QLatin1String("mem_dump")) {
        emit notice(data.value("ok").toBool() ? QStringLiteral("high") : QStringLiteral("high"),
                    data.value("ok").toBool()
                        ? QStringLiteral("memory dump written: %1 (%2 bytes) -- treat as secret")
                              .arg(data.value("path").toString())
                              .arg(data.value("bytes").toLongLong())
                        : QStringLiteral("memory dump failed: %1").arg(data.value("error").toString()));
        emit memReportChanged();
        return;
    }
    if (cmd == QLatin1String("advanced_scan")) {
        const QString verdict = data.value("verdict").toString();
        const QString severity =
            verdict == QLatin1String("MALICIOUS")  ? QStringLiteral("critical")
          : verdict == QLatin1String("suspicious") ? QStringLiteral("high")
                                                   : QStringLiteral("low");
        QString msg = QStringLiteral("%1 \u2014 %2 (risk %3)")
                          .arg(data.value("path").toString(), verdict)
                          .arg(data.value("risk").toLongLong());
        for (const QVariant& rule : data.value("rules").toList())
            msg += QStringLiteral("\nrule: ") + rule.toString();
        if (const QString next = data.value("next_step").toString(); !next.isEmpty())
            msg += QStringLiteral("\nNEXT: ") + next;
        emit notice(severity, msg);
        return;
    }

    if (cmd == QLatin1String("investigate")) {
        emit investigationFinished(data);
        refreshRisk();
        refreshProcesses(300);
        return;
    }
    if (cmd == QLatin1String("decisions.push")) {
        // A single prompt arrived over the push feed; fold it into the panel and
        // raise the modal.
        QMutexLocker lk{&mu_};
        const bool known = std::any_of(decisions_.begin(), decisions_.end(),
                                       [&data](const QVariant& v) {
                                           return v.toMap().value("id").toLongLong() ==
                                                  data.value("id").toLongLong();
                                       });
        if (!known) decisions_.prepend(data);
        emit decisionRequired(data);
        return;
    }
    if (cmd == QLatin1String("selftest")) {
        emit notice(data.value("passed").toBool() ? QStringLiteral("info") : QStringLiteral("critical"),
                    QStringLiteral("self-test: %1 of %2 checks passed")
                        .arg(data.value("checks").toList().size())
                        .arg(data.value("checks").toList().size()));
        return;
    }
    // Every mutating command lands here. The operator needs confirmation that the
    // agent actually did something, including the undo hint when there is one.
    emit actionCompleted(data);
    refreshRemediation();
    refreshRisk();
}

// ---- getters ----
QString Backend::connectionError() const { QMutexLocker lk{&mu_}; return connection_error_; }
QString Backend::version() const { QMutexLocker lk{&mu_}; return version_; }
qint64 Backend::uptime() const noexcept { return uptime_; }
QString Backend::postureLabel() const { QMutexLocker lk{&mu_}; return posture_label_; }
bool Backend::dryRun() const noexcept { return dry_run_; }
bool Backend::autoRespond() const noexcept { return auto_respond_; }
bool Backend::learning() const noexcept { return learning_; }
double Backend::learningProgress() const noexcept { return learning_progress_; }
qint64 Backend::eventsPublished() const noexcept { return published_; }
qint64 Backend::eventsDropped() const noexcept { return dropped_; }
int Backend::sensorsRunning() const noexcept { return sensors_running_; }
int Backend::sensorsDegraded() const noexcept { return sensors_degraded_; }
QVariantMap Backend::toolbox() const { QMutexLocker lk{&mu_}; return toolbox_; }
int Backend::pendingDecisions() const noexcept { return pending_decisions_; }
int Backend::activeBlocks() const noexcept { return active_blocks_; }
int Backend::suspendedPids() const noexcept { return suspended_pids_; }
qint64 Backend::guiClients() const noexcept { return gui_clients_; }
qint64 Backend::guiFrames() const noexcept { return gui_frames_; }
QVariantList Backend::capabilityNotes() const { QMutexLocker lk{&mu_}; return capability_notes_; }
QVariantMap Backend::capabilities() const { QMutexLocker lk{&mu_}; return capabilities_; }
QVariantList Backend::events() const { QMutexLocker lk{&mu_}; return events_; }
QVariantList Backend::sensors() const { QMutexLocker lk{&mu_}; return sensors_; }
QVariantList Backend::riskActors() const { QMutexLocker lk{&mu_}; return risk_actors_; }
QVariantList Backend::decisions() const { QMutexLocker lk{&mu_}; return decisions_; }
QVariantList Backend::remediationActions() const { QMutexLocker lk{&mu_}; return actions_; }
QVariantList Backend::blocks() const { QMutexLocker lk{&mu_}; return blocks_; }
QVariantList Backend::quarantined() const { QMutexLocker lk{&mu_}; return quarantined_; }
QVariantList Backend::listeners() const { QMutexLocker lk{&mu_}; return listeners_; }
QVariantList Backend::connections() const { QMutexLocker lk{&mu_}; return connections_; }
QVariantList Backend::beacons() const
QVariantList Backend::exeBlocks() const { QMutexLocker lk{&mu_}; return exe_blocks_; }
QVariantList Backend::beacons() const { QMutexLocker lk{&mu_}; return beacons_; }
QVariantList Backend::processes() const { QMutexLocker lk{&mu_}; return processes_; }
QVariantList Backend::scanResults() const { QMutexLocker lk{&mu_}; return scan_results_; }
QVariantMap Backend::scanCounters() const { QMutexLocker lk{&mu_}; return scan_counters_; }
QVariantMap Backend::hardening() const { QMutexLocker lk{&mu_}; return hardening_; }
QVariantMap Backend::canaries() const { QMutexLocker lk{&mu_}; return canaries_; }
QVariantMap Backend::baseline() const { QMutexLocker lk{&mu_}; return baseline_; }

QVariantList Backend::featureSettings() const {
    QMutexLocker lk{&mu_};
    return feature_settings_;
}
QVariantMap Backend::riskSummary() const { QMutexLocker lk{&mu_}; return risk_summary_; }
QVariantList Backend::historySeries() const { QMutexLocker lk{&mu_}; return history_series_; }

}  // namespace hyprnova::gui

// moc must see the Q_OBJECT class defined in this .cpp, so include the generated
// unit at the bottom (CMake's AUTOMOC produces moc_backend.cpp for backend.hpp and
// backend.cpp.moc for this file when AUTORCC/AUTOMOC handle it).
#include "backend.moc"
