# CSC3106-MiniProject-GroupQ

## Data-Driven Security Analysis and Defensive Response

This repository contains our group submission for the CSC3106 Cyber Security Fundamentals Mini Project.

The project analyses an assigned Linux authentication log (`auth.log`) using Python to identify suspicious authentication activity, produce evidence-based visualisations, assess cyber security risks, and propose an appropriate technical defensive response.

---

## Project Objectives

### Part 1: Authentication Log Analysis

- Analyse the assigned Linux authentication log
- Identify suspicious authentication behaviour
- Generate reproducible evidence using Python
- Produce visualisations
- Develop an asset-focused risk matrix
- Recommend an initial response

### Part 2: Technical Defensive Response

- Select one prioritised risk from Part 1
- Design an appropriate defensive solution
- Justify the proposed mitigation
- Discuss limitations and trade-offs

---

## Technologies

- Python 3.x
- pandas
- matplotlib
- Regular Expressions (re)
- Git & GitHub

---

## Running the Analysis (Part1)

1. Clone the repository

```bash
git clone <repository-url>
```

2. Install dependencies

```bash
pip install -r requirements.txt
```
3. Packages
```
pandas
matplotlib
```

4. Place the assigned authentication log inside

```
part1/input/
```

5. Run
```bash
python part1/analysis.py
```





```
Generated outputs:
part1/output/parsed_events.csv
part1/output/summary_counts.csv
part1/output/top_source_ips.csv
part1/output/top_targeted_usernames.csv
part1/output/ip_summary.csv
part1/output/failure_success_ips.csv
part1/output/top_source_ips.png
part1/output/failed_attempts_over_time.png

Generated outputs will be saved inside

```



---

## Part 2

Part 2 builds upon one prioritised risk identified in Part 1.
Depending on the selected defensive response, this directory may contain:
- Detection logic
- Configuration files
- Architecture diagrams
- Supporting documentation
- Implementation prototype (if applicable)

## Team Members

| Name | Responsibility |
|------|----------------|
| Haley & Daniel | Part 1: Authentication Log Analysis |
| Chervelle & Jocasta | Part 2: Technical Defensive Response |
| All members | Report Writing & Documentation |

---

## License

This repository is created solely for educational purposes as part of the CSC3106 Cyber Security Fundamentals module at the University of Glasgow and Singapore Institute of Technology.
