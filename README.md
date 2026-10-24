# TETHER: Identity Drift Detection for Autonomous AI Agents

**Team SD Card** (Dev Bajaj, IIT Madras; Sankalp Dawada, DJ Sanghvi College of Engineering) | D3COY 1.0

A valid token says what an agent may touch, not what it is *for*. TETHER is a gateway between an agent and its tools. It holds the real credentials and checks every call against the agent's signed **role contract** and the **origin** of each argument. Untrusted text may supply data, never the arguments that decide where a call goes.

## Run it

```bash
python3 tether_proto.py          # Attack Lab, Python 3.8+, standard library only (about 10 s)
python3 tether_proto.py --live   # one hijacked session in real time (simulated latency, about 6 s)
```

## What is implemented (all in `tether_proto.py`)

| Piece | What it does | Code |
|---|---|---|
| Token binding | HMAC token bound to agent + host; replayed or forged tokens are denied (+20 dB) | `Gateway._decide` |
| Hard policy | Tool and data class must be in the contract; every argument is checked against an explicit rule | `RULES` |
| Provenance (gateway-inferred) | The gateway fetched the document, so it holds every span. For each control argument (vendor, path, URL) it matches the **value** against the mandate and the spans: only a value from the mandate and absent from untrusted text is trusted; a value found in untrusted text, or not traceable anywhere (paraphrased, obfuscated, invented), is held. The agent's own claim about where a value came from is ignored | `Gateway._infer` |
| Clean-room twin (**simulated**) | A rule (does the call match the mandate?) with 97% success per rollout, standing in for 5 independent LLM rollouts that see only the mandate. Approve if at least 4 of 5 pass. It can only tighten, never override a policy deny | `Gateway._twin` |
| Sequential evidence engine | For in-contract events: P_role = (agent counts + 50 x cohort prior) / (N + 50); alternative = 98.6% P_role + 1.4% broad Q; evidence E = product of likelihood ratios; risk = 10 log10(E) dB | `Gateway._stat` |
| Decoys | A decoy vendor that no honest workflow touches; a hit scores through the same evidence engine | `ekey`, `REG` |
| Containment | 20 dB restricts (write, send, sensitive reads off); 35 dB isolates (no more calls run) | `_state` |
| Attribution | Per-target delta debugging over untrusted spans; handles payloads that need several spans together | `ablate` |
| Recovery | Rerun in a fresh session on data-only fields; check the purchase order is correct | `sanitize`, `finish` |
| Change passport | A new tool is allowed only with a signed passport; during probation drift alerts are paused, at ratification the anchor is re-seeded | `Gateway`, `drift_trial` |
| Frozen anchor baseline | Alert when JS divergence between the frozen anchor and the adaptive baseline passes a threshold calibrated on benign runs | `drift_lab` |

## Attack Lab results (seed 7, 50 runs per attack, 300 clean sessions, 200 drift trials per rate)

| Attack | Attempted | Blocked | Leaked | Alarm raised | Span named | Task done after rerun |
|---|---|---|---|---|---|---|
| A1 direct injection (HR read + exfil) | 48 | 48 | 0 | 48 | 48/48 | 48 |
| A2 vendor swap (Zeta Corp or another registered vendor) | 44 | 44 | 0 | 44 | 44/44 | 44 |
| A3 two separate payload spans | 50 | 50 | 0 | 50 | 50/50 | 50 |
| A4 poisoned tool output (exfil) | 47 | 47 | 0 | 47 | 47/47 | 47 |
| A5 joint payload (needs both spans) | 47 | 47 | 0 | 47 | 47/47 | 47 |
| A6 persistent hijack (4 malicious calls) | 49 | 49 | 0 | 49 | 49/49 | 49 |
| A7 token replay / forged token (simulated) | 50 | 50 | 0 | 50 | - | 50 |
| A8 mimicry: in-role call, normal amount | 50 | 0 | 50 | 0 | - | - |
| A9 mimicry: in-role call, unusual amount (249,000) | 50 | 0 | 50 | 0 | - | - |
| A10 agent calls the decoy vendor (value untraceable, decoy evidence scored) | 50 | 50 | 0 | 50 | - | - |
| A11 obfuscated vendor swap (value spelled out letter by letter) | 46 | 46 | 0 | 46 | 46/46 | 46 |

"Attempted" means the scripted agent actually emitted a malicious call (it follows an injection 95% of the time). A single blocked call stays at "watch" (10 dB) by design.

| Other result | Value |
|---|---|
| False alarms on benign sessions | 0 / 300 (300/300 tasks completed) |
| Vendor copied from the quote (valid value, untrusted origin), 100 sessions | strict provenance: 100 false alarms; with the simulated twin: **0** |
| New tool: valid / none / forged passport | 50 / 0 / 0 of 50 allowed |
| Agent-to-agent delegation, run through `Gateway.decide()`: 300 random parent / child / request sets, every tool probed (1500 probes) | 0 escalations (184 calls allowed, all inside request and parent and child contract) |
| Containment enforced (not just recorded) | restricted: write denied, in-role read allowed; isolated: no call runs afterwards |
| Attribution controls | 0 / 50 false attributions on benign sessions; same span set on replay with new seeds 40 / 40 |
| Test-suite self-check | every declared attack (A1-A10) produces its intended malicious calls, asserted per session |
| Slow drift, 0.5% / 1% / 2% per day, 60 days | per-day anomaly check alarms 1% / 2% / 77%; frozen anchor alarms 100% / 100% / 100% (median day 34 / 28 / 23) |
| Drift detector false alarms | per-day 0.5%, anchor 2.0% |
| Legitimate shift: alert without / with ratified passport | 100% / 2% |
| Gateway overhead (measured) | median about 17 us, p99 about 58 us per call (includes value matching against 40 spans) |

## Timing: measured vs simulated

The lab runs in seconds because the scripted agent has no LLM or network wait. A real agent step takes about a second, so the lab uses a **simulated** latency model (agent step about 1.2 s median, tool call about 150 ms). A malicious call is then blocked about 2 s into a session, almost all of it the agent's own thinking time. The only **measured** timing is the gateway's overhead. Attribution replays whole agent rollouts (10 per test, 9 to 74 tests per incident), so it runs in the background.

## Honest limits

- **The agent is a scripted simulator, not an LLM.** These results test gateway logic, not model behavior. A real tool-calling agent is the next step.
- **Token binding is simulated** with HMAC over (agent, host) and a demo-only hard-coded key. There is no issuance, rotation, expiry or replay protection, so it is not production DPoP or mTLS (RFC 9449, 8705).
- **The twin is a simulated rule**, not independent LLM rollouts. It tests the decision logic only.
- **Change passports** test signature validation only. There is no expiry, revocation or full proposed-shadow-probation-ratified lifecycle in code.
- **Attribution ground truth** is the set of spans whose payload produced the blocked call. "Span named" is exact set match on that, and the result is a stochastic replay outcome, checked for false attribution and reproducibility above.
- **Gateway overhead** is the time inside `Gateway.decide()` only (about 3,000 calls, one laptop-class machine, Python 3), not end-to-end latency.
- **Policy-denial weights (10 dB) are hand-set.** The evidence engine's parameters (eta 0.014, nu 50) are the deck's starting values, not tuned. The index is not a calibrated probability.
- **Origin inference is literal value matching.** It fails closed (untraceable means held), but it costs a twin consult on almost every call, because honest values also appear in the quote. A value that equals the mandate's own value is trusted, which is harmless by definition. Real systems would need span-level taint tracking inside the agent for stronger guarantees.
- **In-range mimicry is not caught (A8, A9).** An in-role call with trusted arguments passes every check, and one unusual amount does not move the evidence enough. TETHER limits that damage with least privilege and value limits.
- **Drift results depend on the simulated drift model** (histograms over 5 amount buckets, 60 sessions a day). They show the anchor idea works, not what real traffic looks like.
- **The benign workload is synthetic**, so 0 false alarms here says little about real traffic.
- **Recovery uses a simple field extractor** (regex over known fields), so "task done" shows the flow works, not that arbitrary documents can be cleaned.
- **Not implemented:** the dashboard and the multi-day long-lived-agent statistic (Shiryaev-Roberts form).

## Files

- `tether_proto.py`: gateway, scripted agent simulator, twin, evidence engine, attribution, Attack Lab, drift lab
- `SD_Card_TETHER_D3COY.pptx` / `.pdf`: the screening deck
