# Part 1: Authentication Log Analysis

## Purpose

This script analyses the assigned `4_auth.log` authentication log and generates the evidence used in Part 1 of the report. It extracts selected OpenSSH authentication events, produces summary statistics, and creates the tables and visualisations that support the security analysis.

## How to Run

Complete the project setup described in the root `README.md`, then run:

```bash
python part1/analysis.py
```

## Requirements

- Python 3.10 or later
- Project dependencies listed in `requirements.txt` (see the root `README.md` for installation instructions)

## Input

The script expects the following input file:

```text
part1/input/4_auth.log
```

## Outputs

The script generates the following files in the `part1/output/` directory. These outputs provide the evidence used in Part 1 of the report.

- `parsed_events.csv`
- `summary_counts.csv`
- `ip_summary.csv`
- `top_source_ips.csv`
- `top_targeted_usernames.csv`
- `failure_success_ips.csv`
- `top_source_ips.png`
- `failed_attempts_over_time.png`

## Parsing Assumptions

- The log follows the expected OpenSSH authentication log format.
- Regular expressions are used to identify supported authentication events.
- IPv4 addresses are extracted from recognised log entries.
- The log timestamps do not include a year. Datetime conversion is used only for chronological ordering and hourly grouping of events.

## Limitations

- Only selected OpenSSH authentication events are parsed.
- The script does not process every possible `auth.log` event type.
- The analysis identifies authentication patterns but cannot, on its own, confirm malicious activity or system compromise.
- Results are limited to the supplied log extract.