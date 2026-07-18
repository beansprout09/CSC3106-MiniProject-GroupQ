from pathlib import Path
import sys

import pandas as pd

# ---------------------------------------------------------------------------
# Re-use Part 1's parser so Part 2 evidence is derived from the same
# Python-verified pipeline rather than re-implemented or hand-copied.
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).parent
PART1_DIR = BASE_DIR.parent / "part1"
OUTPUT_DIR = BASE_DIR / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

sys.path.insert(0, str(PART1_DIR))
from analysis import parse_log  # noqa: E402  (Part 1 module, see path setup above)

# ---------------------------------------------------------------------------
# Detection parameters
#
# Modelled on common SSH brute-force protection defaults (e.g. fail2ban's
# sshd jail: maxretry=5 within findtime, then ban for bantime). These are
# configurable constants so a reviewer can retune them for a different log
# or environment.
# ---------------------------------------------------------------------------
MAX_RETRY = 5                    # failed attempts that trigger a block
FIND_TIME = pd.Timedelta(minutes=10)   # rolling window in which they must occur
BAN_TIME = pd.Timedelta(minutes=60)    # how long the source IP is blocked for


def load_events() -> pd.DataFrame:
    """Parse the assigned log using the Part 1 parser and add a datetime column."""
    df = parse_log()
    if df.empty:
        raise SystemExit("No events parsed - check that part1/input/4_auth.log exists.")

    df["datetime"] = pd.to_datetime(
        df["timestamp"], format="%b %d %H:%M:%S", errors="coerce"
    )
    df = df.dropna(subset=["datetime"]).sort_values("datetime").reset_index(drop=True)
    return df


def detect_and_respond(df: pd.DataFrame):
    """
    Replay events in chronological order, per source IP, applying the
    threshold rule. When an IP accumulates MAX_RETRY failed_password events
    within FIND_TIME, an alert/block is triggered and stays active for
    BAN_TIME. Any event from that IP while a block is active is logged as
    'would have been blocked'.
    """
    alerts = []
    blocked_events = []
    summary_rows = []

    for source_ip, group in df.groupby("source_ip"):
        group = group.sort_values("datetime").reset_index(drop=True)

        failed_times = []          # timestamps of failed_password events in current window
        active_block_until = None  # datetime the current block expires, or None
        first_alert_time = None
        first_alert_attempt_count = None
        ever_blocked = False
        accepted_blocked = False
        accepted_unblocked_time = None

        for _, row in group.iterrows():
            ts = row["datetime"]
            event_type = row["event_type"]

            # If a block is currently active, log this event as prevented.
            if active_block_until is not None and ts <= active_block_until:
                blocked_events.append({
                    "source_ip": source_ip,
                    "timestamp": row["timestamp"],
                    "event_type": event_type,
                    "username": row["username"],
                    "block_active_until": active_block_until,
                })
                if event_type == "accepted_password":
                    accepted_blocked = True
                # Blocked connections are not counted further towards new
                # failed-attempt windows; the source is assumed rejected
                # at the network/service level while the block is active.
                continue

            if event_type == "accepted_password" and not accepted_blocked:
                accepted_unblocked_time = ts

            if event_type == "failed_password":
                failed_times.append(ts)
                # Drop attempts that have fallen outside the rolling window.
                failed_times = [t for t in failed_times if ts - t <= FIND_TIME]

                if len(failed_times) >= MAX_RETRY:
                    ever_blocked = True
                    if first_alert_time is None:
                        first_alert_time = ts
                        first_alert_attempt_count = group[
                            (group["event_type"] == "failed_password")
                            & (group["datetime"] <= ts)
                        ].shape[0]

                    alerts.append({
                        "source_ip": source_ip,
                        "trigger_timestamp": row["timestamp"],
                        "attempts_in_window": len(failed_times),
                        "window_minutes": FIND_TIME.total_seconds() / 60,
                        "block_until": ts + BAN_TIME,
                    })
                    active_block_until = ts + BAN_TIME
                    failed_times = []  # reset window after a block is imposed

        summary_rows.append({
            "source_ip": source_ip,
            "total_failed_attempts": int((group["event_type"] == "failed_password").sum()),
            "total_accepted_logins": int((group["event_type"] == "accepted_password").sum()),
            "ever_crossed_threshold": ever_blocked,
            "attempts_before_first_alert": first_alert_attempt_count,
            "first_alert_time": first_alert_time,
            "accepted_login_would_have_been_blocked": accepted_blocked,
            "accepted_login_time_if_not_blocked": accepted_unblocked_time,
        })

    alerts_df = pd.DataFrame(alerts)
    blocked_df = pd.DataFrame(blocked_events)
    summary_df = pd.DataFrame(summary_rows).sort_values(
        by="total_failed_attempts", ascending=False
    )

    return alerts_df, blocked_df, summary_df


def main():
    df = load_events()
    alerts_df, blocked_df, summary_df = detect_and_respond(df)

    alerts_df.to_csv(OUTPUT_DIR / "alerts.csv", index=False)
    blocked_df.to_csv(OUTPUT_DIR / "blocked_events.csv", index=False)
    summary_df.to_csv(OUTPUT_DIR / "detection_summary.csv", index=False)

    print(f"Total alerts (threshold crossings) generated: {len(alerts_df)}")
    print(f"Total events that would have been blocked: {len(blocked_df)}")
    print()

    # Highlight the specific finding this response targets.
    focus = summary_df[summary_df["source_ip"] == "203.0.113.89"]
    if not focus.empty:
        print("Focus IP 203.0.113.89 (Part 1 finding):")
        print(focus.to_string(index=False))
        print()

    would_have_prevented = summary_df[
        summary_df["accepted_login_would_have_been_blocked"]
    ]
    print(f"Accepted logins that would have been prevented by this control: "
          f"{len(would_have_prevented)}")
    if not would_have_prevented.empty:
        print(would_have_prevented[["source_ip", "attempts_before_first_alert",
                                     "first_alert_time"]].to_string(index=False))

    print(f"\nOutputs written to: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
