from pathlib import Path
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.dates as mdates
import matplotlib.pyplot as plt
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

# Source IP selected in Part 1 as the highest-priority finding this
# response addresses (951 failed attempts, then one accepted login).
FOCUS_IP = "203.0.113.89"


def fmt(ts):
    """Format a computed timestamp for display, dropping the placeholder
    year pandas assigns when the source log has no year field."""
    if ts is None or pd.isna(ts):
        return None
    return ts.strftime("%b %d %H:%M:%S")


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
                    "block_active_until": fmt(active_block_until),
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
                        "block_until": fmt(ts + BAN_TIME),
                    })
                    active_block_until = ts + BAN_TIME
                    failed_times = []  # reset window after a block is imposed

        summary_rows.append({
            "source_ip": source_ip,
            "total_failed_attempts": int((group["event_type"] == "failed_password").sum()),
            "total_accepted_logins": int((group["event_type"] == "accepted_password").sum()),
            "ever_crossed_threshold": ever_blocked,
            "attempts_before_first_alert": first_alert_attempt_count,
            "first_alert_time": fmt(first_alert_time),
            "accepted_login_would_have_been_blocked": accepted_blocked,
            "accepted_login_time_if_not_blocked": fmt(accepted_unblocked_time),
        })

    alerts_df = pd.DataFrame(alerts)
    blocked_df = pd.DataFrame(blocked_events)
    summary_df = pd.DataFrame(summary_rows).sort_values(
        by="total_failed_attempts", ascending=False
    )

    return alerts_df, blocked_df, summary_df


def plot_focus_ip_timeline(df: pd.DataFrame, alerts_df: pd.DataFrame, focus_ip: str):
    """
    Plot failed-password attempts, the block windows this control would
    have triggered, and any accepted login, for one source IP - the Part 1
    finding this Part 2 response addresses. Saved as the figure used to
    support the Part 2 evaluation.
    """
    ip_events = df[df["source_ip"] == focus_ip].sort_values("datetime")
    ip_alerts = alerts_df[alerts_df["source_ip"] == focus_ip]
    if ip_events.empty or ip_alerts.empty:
        return

    failed = ip_events[ip_events["event_type"] == "failed_password"]
    accepted = ip_events[ip_events["event_type"] == "accepted_password"]

    windows = [
        (
            pd.to_datetime(row["trigger_timestamp"], format="%b %d %H:%M:%S"),
            pd.to_datetime(row["block_until"], format="%b %d %H:%M:%S"),
        )
        for _, row in ip_alerts.iterrows()
    ]

    fig, ax = plt.subplots(figsize=(10, 3.5))

    for i, (start, end) in enumerate(windows):
        ax.axvspan(start, end, color="red", alpha=0.15,
                   label="Blocked window" if i == 0 else None)
        ax.plot(start, 0, marker="v", color="red", markersize=8,
                label="Block triggered (5 fails / 10 min)" if i == 0 else None)

    ax.plot(failed["datetime"], [0] * len(failed), "|", color="steelblue",
            markersize=14, label="Failed password attempt")

    for _, row in accepted.iterrows():
        ts = row["datetime"]
        inside_block = any(start <= ts <= end for start, end in windows)
        ax.plot(ts, 0, marker="*", color="black", markersize=16,
                label=f"Accepted login ({row['username']})")
        note = f"{ts.strftime('%H:%M:%S')}"
        note += " — inside block window" if inside_block else " — outside any block window"
        ax.annotate(note, xy=(ts, 0), xytext=(0, -30), textcoords="offset points",
                    ha="center", va="top", fontsize=8)

    day_label = ip_events["datetime"].dt.strftime("%d %B").mode().iloc[0]
    ax.set_title(f"Failed attempts, block windows and accepted login for {focus_ip}")
    ax.set_xlabel(f"Time ({day_label})")
    ax.set_yticks([])
    ax.set_ylim(-1, 1)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))

    handles, labels = ax.get_legend_handles_labels()
    by_label = dict(zip(labels, handles))
    ax.legend(by_label.values(), by_label.keys(), loc="upper left", fontsize=8)

    fig.tight_layout()
    fig.savefig(OUTPUT_DIR / "focus_ip_timeline.png", dpi=150)
    plt.close(fig)


def main():
    df = load_events()
    alerts_df, blocked_df, summary_df = detect_and_respond(df)

    alerts_df.to_csv(OUTPUT_DIR / "alerts.csv", index=False)
    blocked_df.to_csv(OUTPUT_DIR / "blocked_events.csv", index=False)
    summary_df.to_csv(OUTPUT_DIR / "detection_summary.csv", index=False)
    plot_focus_ip_timeline(df, alerts_df, FOCUS_IP)

    print(f"Total alerts (threshold crossings) generated: {len(alerts_df)}")
    print(f"Total events that would have been blocked: {len(blocked_df)}")
    print()

    # Highlight the specific finding this response targets.
    focus = summary_df[summary_df["source_ip"] == FOCUS_IP]
    if not focus.empty:
        print(f"Focus IP {FOCUS_IP} (Part 1 finding):")
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
