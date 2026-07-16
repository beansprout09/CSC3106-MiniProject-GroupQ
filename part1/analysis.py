from pathlib import Path
import re
import pandas as pd


BASE_DIR = Path(__file__).parent
LOG_FILE = BASE_DIR / "input" / "4_auth.log"
OUTPUT_DIR = BASE_DIR / "output"

OUTPUT_DIR.mkdir(exist_ok=True)


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

    return pd.DataFrame(events)


def main():
    df = parse_log()

    print(df.head())
    print()
    print("Parsed events:", len(df))
    print(df["event_type"].value_counts())

    df.to_csv(OUTPUT_DIR / "parsed_events.csv", index=False)

    # Generate summary tables
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
    print(top_source_ips.head())

    print("\nTop Targeted Usernames:")
    print(top_usernames.head())

if __name__ == "__main__":
    main()