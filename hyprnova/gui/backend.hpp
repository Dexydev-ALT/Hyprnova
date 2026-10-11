// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 7 — Qt6 backend exposed to QML
//
// THE ONE RULE THIS CLASS EXISTS TO UPHOLD: the QML render thread never blocks.
//
// Every byte of socket I/O, every JSON parse and every snapshot request happens on
// a worker thread. The render thread only ever sees:
//
//   * Q_PROPERTY reads of already-marshalled QVariant values  (no syscall, no lock
//     contention beyond a QMutex held for a pointer swap), and
//   * queued-connection signal deliveries at a rate capped by cfg.gui.telemetry_hz.
//
// A dashboard that drops frames during an incident is worse than no dashboard: the
// operator is looking at it precisely when the host is busiest, which is also when
// the event rate is highest. So the feed is rate-limited on the *producer* side,
// and the lists handed to QML are immutable snapshots replaced wholesale rather
// than mutated in place -- QML's repeaters never observe a half-updated model.
//
// This class is a CLIENT of the agent. It holds no privileges: it connects to the
// agent's AF_UNIX socket and the agent re-authorises every mutating command. That
// means a compromised GUI gets the agent's policy engine, not the agent's root.

#pragma once

#include <QJsonObject>
#include <QJsonArray>
#include <QMutex>
#include <QObject>
#include <QString>
#include <QThread>
#include <QTimer>
#include <QVariantList>
#include <QVariantMap>

#include <atomic>
#include <cstdint>
#include <memory>

namespace hyprnova::gui {

class BackendWorker;

/// Everything QML can see. Registered as a context property named `backend`.
class Backend : public QObject {
    Q_OBJECT

    // ---- connection + headline posture (the big glowing indicator) ----
    Q_PROPERTY(bool connected READ connected NOTIFY connectedChanged)
    Q_PROPERTY(QString connectionError READ connectionError NOTIFY connectionErrorChanged)
    Q_PROPERTY(QString version READ version NOTIFY overviewChanged)
    Q_PROPERTY(qint64 uptime READ uptime NOTIFY overviewChanged)
    Q_PROPERTY(int postureScore READ postureScore NOTIFY overviewChanged)
    Q_PROPERTY(QString postureLabel READ postureLabel NOTIFY overviewChanged)
    Q_PROPERTY(bool dryRun READ dryRun NOTIFY overviewChanged)
    Q_PROPERTY(bool autoRespond READ autoRespond NOTIFY overviewChanged)
    Q_PROPERTY(bool learning READ learning NOTIFY overviewChanged)
    Q_PROPERTY(double learningProgress READ learningProgress NOTIFY overviewChanged)

    // ---- counters for the status bar ----
    Q_PROPERTY(qint64 eventsPublished READ eventsPublished NOTIFY overviewChanged)
    Q_PROPERTY(qint64 eventsDropped READ eventsDropped NOTIFY overviewChanged)
    Q_PROPERTY(int sensorsRunning READ sensorsRunning NOTIFY overviewChanged)
    Q_PROPERTY(int sensorsDegraded READ sensorsDegraded NOTIFY overviewChanged)
    Q_PROPERTY(int pendingDecisions READ pendingDecisions NOTIFY overviewChanged)
    Q_PROPERTY(int activeBlocks READ activeBlocks NOTIFY overviewChanged)
    Q_PROPERTY(int suspendedPids READ suspendedPids NOTIFY overviewChanged)
    Q_PROPERTY(qint64 guiClients READ guiClients NOTIFY overviewChanged)
    Q_PROPERTY(qint64 guiFrames READ guiFrames NOTIFY overviewChanged)

    // ---- capability gaps: shown as a permanent banner, never hidden ----
    Q_PROPERTY(QVariantList capabilityNotes READ capabilityNotes NOTIFY overviewChanged)
    Q_PROPERTY(QVariantMap capabilities READ capabilities NOTIFY overviewChanged)

    // ---- the panels. Immutable snapshots, replaced wholesale. ----
    Q_PROPERTY(QVariantList events READ events NOTIFY eventsChanged)
    Q_PROPERTY(QVariantList sensors READ sensors NOTIFY sensorsChanged)
    Q_PROPERTY(QVariantList riskActors READ riskActors NOTIFY riskChanged)
    Q_PROPERTY(QVariantList decisions READ decisions NOTIFY decisionsChanged)
    Q_PROPERTY(QVariantList remediationActions READ remediationActions NOTIFY remediationChanged)
    Q_PROPERTY(QVariantList blocks READ blocks NOTIFY remediationChanged)
    Q_PROPERTY(QVariantList quarantined READ quarantined NOTIFY remediationChanged)
    Q_PROPERTY(QVariantList listeners READ listeners NOTIFY networkChanged)
    Q_PROPERTY(QVariantList connections READ connections NOTIFY networkChanged)
    Q_PROPERTY(QVariantList beacons READ beacons NOTIFY networkChanged)
    Q_PROPERTY(QVariantList exeBlocks READ exeBlocks NOTIFY networkChanged)
    Q_PROPERTY(QVariantList processes READ processes NOTIFY processesChanged)
    Q_PROPERTY(QVariantList scanResults READ scanResults NOTIFY scansChanged)
    Q_PROPERTY(QVariantMap scanCounters READ scanCounters NOTIFY scansChanged)
    Q_PROPERTY(QVariantMap hardening READ hardening NOTIFY hardeningChanged)
    Q_PROPERTY(QVariantMap toolbox READ toolbox NOTIFY toolboxChanged)
    Q_PROPERTY(QVariantMap canaries READ canaries NOTIFY canariesChanged)
    Q_PROPERTY(QVariantMap baseline READ baseline NOTIFY baselineChanged)
    Q_PROPERTY(QVariantList featureSettings READ featureSettings NOTIFY featureSettingsChanged)
    /// The settings_get reply verbatim (states map + ai_ready/ai_note etc.) --
    /// featureSettings is the curated list; this is everything the daemon said.
    Q_PROPERTY(QVariantMap settingsRaw READ settingsRaw NOTIFY settingsRawChanged)
    Q_PROPERTY(QVariantMap memStatus READ memStatus NOTIFY memStatusChanged)
    Q_PROPERTY(QVariantMap memReport READ memReport NOTIFY memReportChanged)
    Q_PROPERTY(QVariantMap riskSummary READ riskSummary NOTIFY riskChanged)
    Q_PROPERTY(QVariantList historySeries READ historySeries NOTIFY historySeriesChanged)
    // AI analyst / integrations / shadow-copy recovery (GUI completeness batch)
    Q_PROPERTY(QVariantMap aiAnswer READ aiAnswer NOTIFY aiAnswerChanged)
    Q_PROPERTY(QVariantMap toolResult READ toolResult NOTIFY toolResultChanged)
    Q_PROPERTY(QVariantList snapshots READ snapshots NOTIFY snapshotsChanged)
    Q_PROPERTY(QVariantMap snapshotReply READ snapshotReply NOTIFY snapshotReplyChanged)

public:
    explicit Backend(QObject* parent = nullptr);
    ~Backend() override;

    Backend(const Backend&) = delete;
    Backend& operator=(const Backend&) = delete;

    /// Start the worker thread and connect. Safe to call once.
    void start(const QString& socketPath, int refreshHz);
    void shutdown();

    // ---- Q_INVOKABLE: everything QML can ask for ----
    // Read-only refreshes. Each is asynchronous: the property changes when the
    // reply lands, so the caller never waits.
    Q_INVOKABLE void refreshOverview();
    Q_INVOKABLE void refreshSensors();
    Q_INVOKABLE void refreshEvents(int limit = 200);
    Q_INVOKABLE void refreshRisk();
    Q_INVOKABLE void refreshDecisions();
    Q_INVOKABLE void refreshRemediation();
    Q_INVOKABLE void refreshNetwork();
    Q_INVOKABLE void refreshProcesses(int limit = 200);
    Q_INVOKABLE void refreshScans();
    Q_INVOKABLE void refreshHardening();
    Q_INVOKABLE void refreshToolbox();
    Q_INVOKABLE void deepScan(const QString& profile);
    Q_INVOKABLE void refreshCanaries();
    Q_INVOKABLE void refreshBaseline();
    Q_INVOKABLE void refreshAll();

    // Mutating. The agent re-authorises each of these against the peer uid, so a
    // non-root console gets a refusal rather than a silent no-op.
    Q_INVOKABLE void answer(qint64 decisionId, const QString& answer);
    Q_INVOKABLE void investigate(qint64 pid);
    Q_INVOKABLE void resume(qint64 pid);
    Q_INVOKABLE void unblockExe(qint64 id);
    Q_INVOKABLE void blockExe(qint64 pid);
    Q_INVOKABLE void suspend(qint64 pid);
    Q_INVOKABLE void isolate(qint64 pid);
    Q_INVOKABLE void release(qint64 pid);
    Q_INVOKABLE void kill(qint64 pid);
    Q_INVOKABLE void dismiss(qint64 pid);
    Q_INVOKABLE void quarantine(const QString& path);
    Q_INVOKABLE void restore(qint64 id, const QString& to);
    Q_INVOKABLE void block(const QString& ip, int port, qint64 ttlSeconds);
    Q_INVOKABLE void unblock(qint64 id);
    Q_INVOKABLE void harden(const QString& key, const QString& value);
    Q_INVOKABLE void hardenAll();
    Q_INVOKABLE void rescanHardening();
    Q_INVOKABLE void scanPath(const QString& path);
    Q_INVOKABLE void refreshSettings();
    Q_INVOKABLE void setFeature(const QString& key, bool on);
    /// Right-click "Advanced scan": local engine + sha256 + VirusTotal ladder.
    Q_INVOKABLE void advancedScan(const QString& path);
    /// Module 4c: memory forensics surface (status / inspect / opt-in dump).
    Q_INVOKABLE void refreshMemStatus();
    // AI analyst (advises-only; every action still needs an operator).
    Q_INVOKABLE void askAi(const QString& question);
    Q_INVOKABLE void reviewAi(qint64 pid);
    // Ecosystem integrations: run a registered tool, VT hash lookup.
    Q_INVOKABLE void runTool(const QString& name, const QVariantList& args = {});
    Q_INVOKABLE void vtLookup(const QString& sha256);
    // Shadow-copy lifeline (backups + file recovery).
    Q_INVOKABLE void refreshSnapshots();
    Q_INVOKABLE void createSnapshot(const QString& reason);
    Q_INVOKABLE void restoreShadow(const QString& id, const QString& to);
    Q_INVOKABLE void verifySnapshot(const QString& id);
    Q_INVOKABLE void inspectMemory(qint64 pid);
    Q_INVOKABLE void dumpMemory(qint64 pid);
    [[nodiscard]] QVariantMap memStatus() const;
    [[nodiscard]] QVariantMap memReport() const;
    Q_INVOKABLE void fullSweep();
    Q_INVOKABLE void plantCanaries();
    Q_INVOKABLE void reloadConfig();
    Q_INVOKABLE void runSelfTest();

    /// Process-tree helper: returns the direct children of `pid` from the cached
    /// process snapshot. Cached rather than queried, because a tree view calls it
    /// once per expanded node per repaint.
    Q_INVOKABLE QVariantList childrenOf(qint64 pid) const;
    /// Ancestry chain for the threat dialog's lineage breadcrumb.
    Q_INVOKABLE QVariantList lineageOf(qint64 pid) const;

    // ---- getters ----
    [[nodiscard]] bool connected() const noexcept { return connected_; }
    [[nodiscard]] QString connectionError() const;
    [[nodiscard]] QString version() const;
    [[nodiscard]] qint64 uptime() const noexcept;
    [[nodiscard]] int postureScore() const noexcept { return posture_score_; }
    [[nodiscard]] QString postureLabel() const;
    [[nodiscard]] bool dryRun() const noexcept;
    [[nodiscard]] bool autoRespond() const noexcept;
    [[nodiscard]] bool learning() const noexcept;
    [[nodiscard]] double learningProgress() const noexcept;
    [[nodiscard]] qint64 eventsPublished() const noexcept;
    [[nodiscard]] qint64 eventsDropped() const noexcept;
    [[nodiscard]] int sensorsRunning() const noexcept;
    [[nodiscard]] int sensorsDegraded() const noexcept;
    [[nodiscard]] int pendingDecisions() const noexcept;
    [[nodiscard]] int activeBlocks() const noexcept;
    [[nodiscard]] int suspendedPids() const noexcept;
    [[nodiscard]] qint64 guiClients() const noexcept;
    [[nodiscard]] qint64 guiFrames() const noexcept;
    [[nodiscard]] QVariantList capabilityNotes() const;
    [[nodiscard]] QVariantMap capabilities() const;
    [[nodiscard]] QVariantMap settingsRaw() const;
    [[nodiscard]] QVariantList events() const;
    [[nodiscard]] QVariantMap aiAnswer() const;
    [[nodiscard]] QVariantMap toolResult() const;
    [[nodiscard]] QVariantList snapshots() const;
    [[nodiscard]] QVariantMap snapshotReply() const;
    [[nodiscard]] QVariantList sensors() const;
    [[nodiscard]] QVariantList riskActors() const;
    [[nodiscard]] QVariantList decisions() const;
    [[nodiscard]] QVariantList remediationActions() const;
    [[nodiscard]] QVariantList blocks() const;
    [[nodiscard]] QVariantList quarantined() const;
    [[nodiscard]] QVariantList listeners() const;
    [[nodiscard]] QVariantList connections() const;
    [[nodiscard]] QVariantList beacons() const;
    [[nodiscard]] QVariantList exeBlocks() const;
    [[nodiscard]] QVariantList processes() const;
    [[nodiscard]] QVariantList scanResults() const;
    [[nodiscard]] QVariantMap scanCounters() const;
    [[nodiscard]] QVariantMap hardening() const;
    [[nodiscard]] QVariantMap toolbox() const;
    [[nodiscard]] QVariantMap canaries() const;
    [[nodiscard]] QVariantMap baseline() const;
    [[nodiscard]] QVariantList featureSettings() const;
    [[nodiscard]] QVariantMap memStatus() const;
    [[nodiscard]] QVariantMap memReport() const;
    [[nodiscard]] QVariantMap riskSummary() const;
    [[nodiscard]] QVariantList historySeries() const;

signals:
    void connectedChanged();
    void connectionErrorChanged();
    void overviewChanged();
    void eventsChanged();
    void settingsRawChanged();
    void aiAnswerChanged();
    void toolResultChanged();
    void snapshotsChanged();
    void snapshotReplyChanged();
    void sensorsChanged();
    void riskChanged();
    void decisionsChanged();
    void remediationChanged();
    void networkChanged();
    void processesChanged();
    void scansChanged();
    void hardeningChanged();
    void toolboxChanged();
    void canariesChanged();
    void baselineChanged();
    void featureSettingsChanged();
    void memStatusChanged();
    void memReportChanged();
    void historySeriesChanged();

    /// A new escalation prompt. The QML side opens a modal ThreatDialog: this is
    /// the one notification that must interrupt whatever the operator is doing.
    void decisionRequired(QVariantMap decision);
    /// Any completed agent action, for the toast stack in the bottom-right.
    void actionCompleted(QVariantMap action);
    /// Free-form operator notice ("reload failed", "sensor degraded").
    void notice(QString severity, QString message);
    /// Result of an `investigate` call, which is too large for a toast.
    void investigationFinished(QVariantMap report);

private:
    // Slots invoked on the MAIN thread via queued connections from the worker.
    void onConnected(bool ok, QString error);
    void onOverview(QVariantMap data);
    void onEvents(QVariantList data);
    void onTelemetry(QVariantMap event);
    void onSensors(QVariantList data);
    void onRisk(QVariantMap data);
    void onDecisions(QVariantList data);
    void onRemediation(QVariantMap data);
    void onNetwork(QVariantMap data);
    void onProcesses(QVariantList data);
    void onScans(QVariantMap data);
    void onHardening(QVariantMap data);
    void onCanaries(QVariantMap data);
    void onBaseline(QVariantMap data);
    void onSettings(QVariantMap data);
    void onMemStatus(QVariantMap data);
    void onMemInspect(QVariantMap data);
    void onMemDump(QVariantMap data);
    void onReply(QString cmd, bool ok, QVariantMap data, QString error);

    void send(const QJsonObject& request);
    void applyTelemetryRate();

    std::unique_ptr<BackendWorker> worker_;
    QThread worker_thread_;
    QTimer poll_;

    // Guarded by mu_. Written only from the queued slots (main thread), read by
    // QML property getters (also main thread), so the mutex is belt-and-braces for
    // the worker's occasional direct read of connected_.
    mutable QMutex mu_;
    bool connected_{false};
    QString connection_error_;
    QVariantMap overview_;
    QVariantList events_;
    QVariantMap settings_raw_;
    QVariantMap ai_answer_;
    QVariantMap tool_result_;
    QVariantList snapshots_;
    QVariantMap snapshot_reply_;
    QVariantList sensors_;
    QVariantList risk_actors_;
    QVariantMap risk_summary_;
    QVariantList decisions_;
    QVariantList actions_;
    QVariantList blocks_;
    QVariantList quarantined_;
    QVariantList listeners_;
    QVariantList connections_;
    QVariantList beacons_;
    QVariantList exe_blocks_;
    QVariantList processes_;
    QVariantList scan_results_;
    QVariantMap scan_counters_;
    QVariantMap hardening_;
    QVariantMap toolbox_;
    QVariantMap canaries_;
    QVariantMap baseline_;
    QVariantList feature_settings_;
    QVariantMap mem_status_;
    QVariantMap mem_report_;
    QVariantList history_series_;

    // Cached scalars so a repaint never touches the JSON DOM.
    int posture_score_{0};
    QString posture_label_;
    QString version_;
    qint64 uptime_{0};
    qint64 published_{0};
    qint64 dropped_{0};
    int sensors_running_{0};
    int sensors_degraded_{0};
    int pending_decisions_{0};
    int active_blocks_{0};
    int suspended_pids_{0};
    qint64 gui_clients_{0};
    qint64 gui_frames_{0};
    bool dry_run_{false};
    bool auto_respond_{false};
    bool learning_{false};
    double learning_progress_{0.0};
    QVariantList capability_notes_;
    QVariantMap capabilities_;

    int refresh_hz_{4};
    std::atomic<qint64> telemetry_pending_{0};
};

}  // namespace hyprnova::gui
