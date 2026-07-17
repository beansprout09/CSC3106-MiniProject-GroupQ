from pathlib import Path
import re
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

# File paths
BASE_DIR = Path(__file__).parent
LOG_FILE = BASE_DIR / "input" / "4_auth.log"
OUTPUT_DIR = BASE_DIR / "output"

OUTPUT_DIR.mkdir(exist_ok=True)

# Parse authentication log
def parse_log():
    events = []

    failed_pattern = re.compile(
        r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*"
        r"Failed password for (?P<username>\S+) from "
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)"
    )

    accepted_pattern = re.compile(
        r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*"
        r"Accepted password for (?P<username>\S+) from "
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)"
    )

    invalid_user_pattern = re.compile(
        r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*"
        r"Invalid user (?P<username>\S+) from "
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)"
    )

    max_attempts_pattern = re.compile(
        r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*"
        r"maximum authentication attempts exceeded for "
        r"(?P<username>\S+) from "
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)"
    )

    connection_closed_pattern = re.compile(
        r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*"
        r"Connection closed by authenticating user "
        r"(?P<username>\S+) "
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)"
    )

    with LOG_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            match = failed_pattern.search(line)
            if match:
                events.append({
                    "timestamp": match.group("timestamp"),
                    "event_type": "failed_password",
                    "username": match.group("username"),
                    "source_ip": match.group("ip"),
                    "raw_line": line
                })
                continue

            match = accepted_pattern.search(line)
            if match:
                events.append({
                    "timestamp": match.group("timestamp"),
                    "event_type": "accepted_password",
                    "username": match.group("username"),
                    "source_ip": match.group("ip"),
                    "raw_line": line
                })
                continue

            match = invalid_user_pattern.search(line)
            if match:
                events.append({
                    "timestamp": match.group("timestamp"),
                    "event_type": "invalid_user",
                    "username": match.group("username"),
                    "source_ip": match.group("ip"),
                    "raw_line": line
                })
                continue

            match = max_attempts_pattern.search(line)
            if match:
                events.append({
                    "timestamp": match.group("timestamp"),
                    "event_type": "maximum_auth_attempts",
                    "username": match.group("username"),
                    "source_ip": match.group("ip"),
                    "raw_line": line
                })
                continue

            match = connection_closed_pattern.search(line)
            if match:
                events.append({
                    "timestamp": match.group("timestamp"),
                    "event_type": "connection_closed_preauth",
                    "username": match.group("username"),
                    "source_ip": match.group("ip"),
                    "raw_line": line
                })

    return pd.DataFrame(events)


# Main analysis
def main():
    df = parse_log()

    if df.empty:
        print("No matching authentication events were found.")
        return

    print(df.head())
    print()
    print("Parsed events:", len(df))
    print(df["event_type"].value_counts())

    # Save all parsed events
    df.to_csv(
        OUTPUT_DIR / "parsed_events.csv",
        index=False
    )

    # Basic summary tables
    failed_df = df[df["event_type"] == "failed_password"]

    top_source_ips = (
        failed_df["source_ip"]
        .value_counts()
        .rename_axis("source_ip")
        .reset_index(name="failed_attempts")
    )

    top_usernames = (
        failed_df["username"]
        .value_counts()
        .rename_axis("username")
        .reset_index(name="failed_attempts")
    )

    summary_counts = (
        df["event_type"]
        .value_counts()
        .rename_axis("event_type")
        .reset_index(name="count")
    )

    top_source_ips.to_csv(
        OUTPUT_DIR / "top_source_ips.csv",
        index=False
    )

    top_usernames.to_csv(
        OUTPUT_DIR / "top_targeted_usernames.csv",
        index=False
    )

    summary_counts.to_csv(
        OUTPUT_DIR / "summary_counts.csv",
        index=False
    )

    print("\nTop Source IPs:")
    print(top_source_ips.head(10))

    print("\nTop Targeted Usernames:")
    print(top_usernames.head(10))

    # -----------------------------------------------------
    # IP behavioural summary
    # -----------------------------------------------------

    # These event types represent attempts to target accounts.
    targeting_events = df[
        df["event_type"].isin([
            "failed_password",
            "invalid_user",
            "maximum_auth_attempts"
        ])
    ]

    # Count the number of unique usernames targeted by each IP.
    unique_users_by_ip = (
        targeting_events
        .groupby("source_ip")["username"]
        .nunique()
        .rename("unique_users_targeted")
    )

    # Combine the authentication behaviour of each source IP.
    ip_summary = (
        df.groupby("source_ip")
        .agg(
            failed_attempts=(
                "event_type",
                lambda values: (values == "failed_password").sum()
            ),
            accepted_logins=(
                "event_type",
                lambda values: (values == "accepted_password").sum()
            ),
            invalid_user_events=(
                "event_type",
                lambda values: (values == "invalid_user").sum()
            ),
            max_auth_attempts=(
                "event_type",
                lambda values: (
                    values == "maximum_auth_attempts"
                ).sum()
            ),
            connection_closed_preauth=(
                "event_type",
                lambda values: (
                    values == "connection_closed_preauth"
                ).sum()
            )
        )
        .join(unique_users_by_ip)
        .fillna({"unique_users_targeted": 0})
        .reset_index()
    )

    ip_summary["unique_users_targeted"] = (
        ip_summary["unique_users_targeted"].astype(int)
    )

    ip_summary = ip_summary.sort_values(
        by=[
            "failed_attempts",
            "max_auth_attempts",
            "invalid_user_events"
        ],
        ascending=False
    )

    ip_summary.to_csv(
        OUTPUT_DIR / "ip_summary.csv",
        index=False
    )

    print("\nIP Summary:")
    print(ip_summary.head(10))

    # -----------------------------------------------------
    # Failure-success correlation
    # -----------------------------------------------------

    # These IPs produced both failed and accepted authentication events. 
    # This does not prove compromise, but the activity should be investigated further.
    failure_success_ips = ip_summary[
        (ip_summary["failed_attempts"] > 0)
        & (ip_summary["accepted_logins"] > 0)
    ].copy()

    failure_success_ips = failure_success_ips.sort_values(
        by=["failed_attempts", "accepted_logins"],
        ascending=[False, False]
    )

    failure_success_ips.to_csv(
        OUTPUT_DIR / "failure_success_ips.csv",
        index=False
    )

    print("\nIPs with both failed and accepted logins:")
    print(
        failure_success_ips[
            [
                "source_ip",
                "failed_attempts",
                "accepted_logins",
                "invalid_user_events",
                "max_auth_attempts",
                "unique_users_targeted"
            ]
        ].head(20)
    )

    # -----------------------------------------------------
    # Visualisation 1: Top source IPs by failed attempts
    # -----------------------------------------------------

    top_ips_plot = (
        top_source_ips
        .head(10)
        .sort_values("failed_attempts")
    )

    fig, ax = plt.subplots(figsize=(10, 6))

    bars = ax.barh(
        top_ips_plot["source_ip"],
        top_ips_plot["failed_attempts"]
    )

    ax.bar_label(bars, padding=3)

    ax.set_title(
        "Top Source IPs by Failed Authentication Attempts"
    )
    ax.set_xlabel("Number of failed authentication attempts")
    ax.set_ylabel("Source IP address")
    ax.grid(axis="x", alpha=0.25)

    fig.tight_layout()
    fig.savefig(
        OUTPUT_DIR / "top_source_ips.png",
        dpi=300,
        bbox_inches="tight"
    )
    plt.close(fig)

    # -----------------------------------------------------
    # Visualisation 2: Failed attempts over time
    # -----------------------------------------------------

    failed_over_time = failed_df.copy()

    # The source timestamps do not include a year.
    # Datetime conversion is used only to order and group events.
    failed_over_time["datetime"] = pd.to_datetime(
        failed_over_time["timestamp"],
        format="%b %d %H:%M:%S",
        errors="coerce"
    )

    hourly_failures = (
        failed_over_time
        .dropna(subset=["datetime"])
        .set_index("datetime")
        .resample("h")
        .size()
    )

    fig, ax = plt.subplots(figsize=(11, 5))

    ax.plot(
        hourly_failures.index,
        hourly_failures.values,
        marker="o",
        linewidth=1.5,
        markersize=3
    )

    ax.set_title("Failed Authentication Attempts Over Time")
    ax.set_xlabel("Time — hourly intervals")
    ax.set_ylabel("Failed authentication attempts")
    ax.xaxis.set_major_formatter(
        mdates.DateFormatter("%b %d\n%H:%M")
    )
    ax.grid(axis="y", alpha=0.25)

    fig.autofmt_xdate(rotation=0)
    fig.tight_layout()
    fig.savefig(
        OUTPUT_DIR / "failed_attempts_over_time.png",
        dpi=300,
        bbox_inches="tight"
    )
    plt.close(fig)

    print("\nVisualisations saved successfully.")

    print("\nAnalysis completed successfully.")
    print(f"Outputs saved to: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()