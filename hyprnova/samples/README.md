# Test samples

`sandbox/` contains BEHAVIOURAL TEST FIXTURES, not malware and not EICAR.

* `systemupdate.c` — a trojan that masquerades as a system updater: embedded
  high-entropy "packed stage" (generated random bytes, `payload_blob.h`),
  mass high-entropy rewrite of `/tmp/sbx/victims/*` with `.locked` renames,
  a `README_RESTORE.txt` ransom note, `/bin/sh -c rm -rf` backup destruction
  and a localhost beacon loop. Damages ONLY /tmp/sbx paths, and only when you
  run it. HyprNova's detectors must catch it on execution like any unknown:
  proc-poll attributes the process, the trait rules and entropy score it,
  heuristics freeze it, and the operator decides.
* `photo-backup.c` — benign control: slow, low-entropy library sync. Must run
  to completion with ZERO alerts (the false-positive tripwire).

Rebuild after editing: `cc -O0 -o systemupdate systemupdate.c` (regenerate
`payload_blob.h` via the snippet in git history if the entropy ever drops
below 7.5).
