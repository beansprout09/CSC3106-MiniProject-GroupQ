# Part 2 — Technical Defensive Response

## What this addresses

This builds on the Part 1 finding that source IP `203.0.113.89` generated 951
failed SSH password attempts against `backup01` (mostly against the `backup`
account) and then successfully authenticated once, with no rate limiting or
automatic blocking in place to stop it.

## What the script does

`detect_and_respond.py` re-uses the Part 1 parser (`part1/analysis.py`) to
read the assigned log, then replays events in time order per source IP,
applying threshold-based brute-force detection modelled on common SSH
intrusion-prevention practice (fail2ban-style: 5 failed attempts from one
source IP within a 10-minute window triggers a 60-minute block). Any
subsequent event from that IP while the block is active — including a
login that would otherwise have been accepted — is logged as prevented.

This is a **log-replay simulation**, not a live control. It does not
connect to, scan, or modify any system. It is used to produce evidence of
what an automated blocking control would have done had it been running
during the period covered by the log, per the assessment's requirement not
to interact with live systems.

## How to run

```
python part2/detect_and_respond.py
```

Requires the same environment as Part 1 (`pandas`), and expects
`part1/input/4_auth.log` and `part1/analysis.py` to be present (the script
imports `parse_log` from Part 1 rather than re-implementing parsing).

## Outputs (`part2/output/`)

- `alerts.csv` — every time a source IP crosses the 5-attempts/10-minute
  threshold and a 60-minute block is triggered, with the trigger time and
  block expiry.
- `blocked_events.csv` — every event from a source IP that occurred while a
  block was active, i.e. would have been rejected.
- `detection_summary.csv` — one row per source IP, showing total failed
  attempts, whether it ever crossed the threshold, how many attempts it took
  to first trigger a block, and whether any accepted login would have been
  blocked by this control.

## Key result

`203.0.113.89` crossed the detection threshold after only 5 failed attempts
(02:05:48), and was blocked four separate times over the ~3.5-hour attack
window as it kept retrying. Its one successful login, at 03:08:19 for the
`backup` account, falls inside one of those active block windows — so this
control would have prevented the successful authentication entirely.

## Parameters and why

- `MAX_RETRY = 5`, `FIND_TIME = 10 minutes` — matches fail2ban's default
  sshd jail thresholds, a widely used baseline for SSH brute-force
  detection.
- `BAN_TIME = 60 minutes` — long enough to break up a sustained scripted
  attack (the observed attack ran continuously in short bursts), short
  enough that a legitimate user who is genuinely locked out is not blocked
  indefinitely.

These are configurable constants at the top of the script, so a reviewer
can retune them for a different log or environment.

## Limitations

- Thresholds are static and were not tuned against a labelled dataset of
  this specific environment's normal login behaviour; a legitimate user who
  mistypes their password 5 times in 10 minutes would also be blocked
  (false positive).
- IP-based blocking does not stop an attacker who rotates source addresses,
  and does not address credential weakness itself (rotating the `backup`
  account's password/key is still required).
- This is a detective/preventive control for the authentication layer only;
  it does not verify what the attacker did after the single accepted login
  in the underlying log period, since the assigned extract does not include
  post-authentication activity.
