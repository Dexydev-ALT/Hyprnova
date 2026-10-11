# HyprNova — Gap Analysis (2026-10-10)

Priority: **P0** release blocker · **P1** must for RC · **P2** wanted · **P3** deferred.

| # | Area | Gap | P | Plan |
|---|------|-----|---|------|
| 1 | Memory forensics | In-process inspection exists only inside the escalation pipeline; no user-facing status/inspect/dump; no external-tool inventory; GUI page missing | **P0** | `forensics/mem_inspect` module + CLI `mem-status/mem-inspect/mem-dump` + bridge + **MemoryForensicsPage.qml** (this batch) |
| 2 | Response safety | PID-reuse revalidation before signals (F1) | **P0** | this batch |
| 3 | Quarantine safety | restore hash-verify + occupied-destination guard (F2) | **P0** | this batch |
| 4 | Testing infra | No tests/ directory, no runner, no machine-readable output | **P0** | `tests/` + `hyprnova-tests` binary + runner + first suites (this batch); 1,000-case target tracked in TEST_PLAN.md |
| 5 | Version control | No git repo (F4) | **P0** | init + full commit (this batch) |
| 6 | Rescue E2E | DONE 2026-10-10: live E2E (fixture report -> per-finding high events + .consumed rename; malformed kept + WARN); findings array added to cleaner script; /var/lib fallback; stale validate() msg fixed; save/load roundtrip now enforced by tests (caught + fixed log_level & scan.backend serializer bugs) | P1 | done |
| 7 | Packaging | unit BUILT+verified; .deb BUILT (conffile, purge archives recovery data); RPM spec written; real installs NOT RUN (need disposable VM) | P1 | done/NOT-RUN-documented | next batch (needs disposable VM for service tests → partly NOT RUN here) |
| 8 | GUI pages | Memory (→ now), AI analyst, Integrations, Backups, File recovery, Ransomware-incident timeline | P1 | DONE 2026-10-10: all five remaining pages built (AiAnalyst, Integrations, Backups, FileRecovery, Timeline) + backend invokables; nav 16 pages; QML loader 33/33 |
| 9 | Detection corpus | Fixtures exist ad hoc in samples/; no versioned corpus with expected outcomes | P1 | DONE 2026-10-10: tests/corpus (10 synthetic fixtures + MANIFEST.json) enforced by test_corpus.cpp against the built-in rule floor; trait fixtures c2/miner/rootkit (batch-2 open item) closed |
| 10 | File carving | Tools registered, no opt-in workflow | P2 | after corpus |
| 11 | Honeypots | Cowrie/OpenCanary registered; fake configs absent | P2 | |
| 12 | nftables by-exe policy | DONE 2026-10-10: BlockExe/UnblockExe (cgroup v2 + nftables cgroupv2 match), auto/manual escalation, CLI+GUI verbs, 25 unit cases; kernel side VM-gated NOT RUN | P2 | |
| 13 | Malware-analysis sandbox | DONE 2026-10-10: tools/analysis module (analysis-plan + sandbox-cmd workflows, deep links, firejail/bwrap argv builders, detonation policy note); Ghidra/AFL++/QEMU install themselves stays env-gated and probed honestly | P2 | |
| 14 | Metrics/benchmark | DONE 2026-10-10: hyprnova-bench (sha256/json/bus-latency/carver/honeypot benches, human+JSON reports, --quick); shape-pinned in suite; numbers honestly environment-specific | P2 | after corpus (spec §9) |
| 15 | Heartbeat removal | Deliberately kept until release (owner instruction) | P3 | at RC |
