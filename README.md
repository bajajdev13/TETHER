# TETHER: Identity Drift Detection for Autonomous AI Agents

**Team SD Card** (Dev Bajaj, IIT Madras; Sankalp Dawada, DJ Sanghvi College of Engineering) | D3COY 1.0

A valid token says what an agent may touch, not what it is *for*. TETHER is a gateway that sits between an agent and its tools, holds the real credentials, and checks every call against the agent's signed **role contract** and the **origin** of each argument. Untrusted text may supply data, never the arguments that decide where a call goes.

## Run it

```bash
python3 tether_proto.py      # Python 3.8+, standard library only, about 10 seconds
```

## What it does

| Stage | What happens | Code |
|---|---|---|
| 1. Hard policy | Deterministic check: tool, data class, destination, value limit. A deny here is final. | `check()` |
| 2. Argument provenance | Control arguments (vendor, path, URL) must not originate in untrusted spans. | `check()` |
| 3. Risk index | Each blocked call adds 10 dB of evidence. 10 = watch, 20 = restrict, 35 = isolate. | `run_session()` |
| 4. Investigate | Ablation replay: recursive halving over untrusted spans names the guilty one(s) in about O(g log n) replays. | `ablate()` |
| 5. Contain | Restrict or isolate the session, then rerun the task on data-only input. | `run_session()` |

## Attack Lab (6 attacks x 50 runs, 300 clean sessions)

| Result | Value |
|---|---|
| Attacks that executed and were blocked | 245 / 245 (A1-A5) |
| Guilty span named exactly | 195 / 195, median 12 replays (naive: 40) |
| False alarms on clean sessions | 0 / 300 |
| Legitimate tasks completed | 300 / 300 |
| New agent, no history | 50 / 50 blocked |
| Child agent exceeds parent mandate | 50 / 50 denied |
| Mimicry inside the contract (A6) | 0 / 50 caught (expected, see limits) |
| Contract + origin check | about 0.35 us per call (Python, excludes network) |

## Honest limits

- **The agent is scripted, not an LLM.** It follows injected instructions 95% of the time. The numbers test the *gateway logic*, not model behavior. Real-LLM runs are the next step.
- **Risk weights are hand-set** (10 dB per blocked call). It is a provisional index, not a calibrated probability.
- **Not implemented in this prototype:** the sequential-test evidence engine, the clean-room twin, decoy assets, Change Passports and the dashboard. They are in the design (see the deck), not in this file.
- **What no behavior monitor can catch:** an in-role action whose arguments all come from trusted sources (A6). TETHER limits the damage with least privilege and value limits.
- The latency figure is a micro-benchmark of one function.

## Files

- `tether_proto.py`: gateway, scripted agent, ablation, Attack Lab
- `SD_Card_TETHER_D3COY_v2.pptx` / `.pdf`: the screening deck
