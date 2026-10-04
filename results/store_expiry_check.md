# Sorted-set expiry: the memory store against Redis (sixth-round follow-up)

The simulator runs on `MemoryStore`, which keeps a sorted set's expiry from the write that created it;
`RedisStore` (Redis `EXPIRE` on every `ZADD`) refreshes it on every write. Sorted sets with an expiry are
used by the outage detector (`outage:*`, expiry twice their window) and by Step 5's number-pattern
checks (`numseq:*`, `numpfx:*`). In a simulated run these sets therefore empty a fixed time after their
first write, whatever arrived since; on Redis they persist while written to.

To measure what the difference does to the recorded results, the 102-run reproduction sample of
`results/reproduction_check.md` (three runs per study, both result files, seed 20261003) was replayed
with the memory store changed to refresh the expiry on every write, as Redis does (patch below, applied
to 2.8.2 in a separate worktree; not part of any release). Result: **75 of 102 runs identical**, 27
different:

- 16 only in the count of outage alerts (in a 24-hour legitimate-only run, for example, 38 alerts
  against 6);
- 7 in which step stopped requests, the friction applied or the block-verdict counts, with leakage
  unchanged;
- 4 in leakage, where an outage suspension of the block tests did or did not happen, or Step 5's
  number-pattern sets kept more history: matched-comparison tuning seed 101, 268 messages against 21;
  E5 tuning seed 101, 218 against 127; E2 seed 6301, 559 against 524; E1 seed 304, 3 179 against 3 167.

Making only the outage detector's distinct-block set refresh (an early version of `store.zadd_max`)
changed 18 of the 102 (`CHANGELOG.md`, 2.8.2). The recorded results are those of the memory store's
rule; aligning it with Redis means rerunning the studies and is not done in 2.8.2.

Differing runs (the first three differing fields of each, as `scripts/check_reproduction.py` reports them):

| Results file | Study | Spec hash | Seed | Outcome |
|---|---|---|---:|---|
| evaluation | alternatives | e6b06e07b961 | 4 | /attack/stopped_by/sent:sms:allow, /attack/stopped_by/sent:sms:delay, /outage_alerts |
| evaluation | alternatives_fp | 858ad8cabd95 | 1 | /outage_alerts |
| evaluation | alternatives_fp | 5786c93d8cce | 3 | /outage_alerts |
| evaluation | alternatives_fp | 696ecffcb1df | 2 | /friction/added_delay_s_total, /friction/by_channel/sms, /friction/challenge_rate_pct |
| evaluation | fallback | 307b6c8ef3c3 | 1 | /outage_alerts |
| evaluation | fallback | 83905f0da1bb | 1 | /block_verdicts, /block_verdicts_incl_drain, /blocks_with_verdict |
| evaluation | fallback | 63820f44a7b8 | 2 | /outage_alerts |
| evaluation | legit24h | 5e0e63b52cd8 | 2 | /outage_alerts |
| evaluation | legit24h | 33cfee42b113 | 3 | /outage_alerts |
| evaluation | legit24h | d88f8012e556 | 3 | /block_verdicts, /block_verdicts_incl_drain, /blocks_with_verdict |
| evaluation | long_attack | 01e9afb323d0 | 0 | /attack/stopped_by/sent:sms:allow, /attack/stopped_by/sent:sms:delay |
| evaluation | long_attack | 052ed3d5b20e | 7 | /outage_alerts |
| evaluation | matched_tuning | 6c8ec390d48f | 101 | /attack/cost_usd, /attack/leaked_before_containment, /attack/leaked_per_min |
| evaluation | pumping | 17302149654c | 7 | /outage_alerts |
| evaluation | pumping | 27d31de47c87 | 4 | /outage_alerts |
| counter study | E1 | cda7883d9038 | 304 | /attack/cost_usd, /attack/leaked_before_containment, /attack/leaked_per_min |
| counter study | E2 | c4e1e0344778 | 6301 | /attack/cost_usd, /attack/leaked_before_containment, /attack/leaked_per_min |
| counter study | E2 | f304a25adfef | 6401 | /attack/stopped_by/sent:sms:allow, /attack/stopped_by/sent:sms:delay |
| counter study | E3 | c176903635f3 | 305 | /outage_alerts |
| counter study | E4 | 73a48a448391 | 300 | /outage_alerts |
| counter study | E4 | 4c0f5009e82c | 300 | /attack/stopped_by/sent:sms:allow, /attack/stopped_by/sent:sms:delay, /outage_alerts |
| counter study | E5_eval | 5bb58462b408 | 305 | /outage_alerts |
| counter study | E5_eval | 5e41a7f6ad93 | 301 | /outage_alerts |
| counter study | E5_eval | 9a5fb3d24591 | 306 | /outage_alerts |
| counter study | E5_tuning | 026b3c308529 | 101 | /attack/cost_usd, /attack/leaked_before_containment, /attack/leaked_per_min |
| counter study | E5_tuning | 866607d80552 | 102 | /outage_alerts |
| counter study | E5_tuning | 86c11622315c | 100 | /outage_alerts |

Patch used for the measurement:

```diff
diff --git a/src/otp_guard/store.py b/src/otp_guard/store.py
index d3ecc40..59b13b5 100644
--- a/src/otp_guard/store.py
+++ b/src/otp_guard/store.py
@@ -261,6 +261,8 @@ class MemoryStore:
                 self._put(key, {member: score}, ttl=ttl)
             else:
                 v[0][member] = score
+                if ttl:
+                    self._d[key] = (v[0], self.clock.now() + ttl)      # refresh, as Redis does
 
     def zadd_max(self, key, score, member, ttl=None):
         """Add member, or raise its score to `score`; never lower it (see LUA_ZADD_MAX). Like zadd above,
@@ -272,6 +274,8 @@ class MemoryStore:
                 self._put(key, {member: score}, ttl=ttl)
             elif member not in v[0] or v[0][member] < score:
                 v[0][member] = score
+            if v is not None and ttl:
+                self._d[key] = (self._d[key][0], self.clock.now() + ttl)    # refresh, as Redis does
 
     def zrangebyscore(self, key, lo, hi):
         with self.lock:
```
