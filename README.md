# CSC3106-MiniProject-GroupQ

## Data-Driven Security Analysis and Defensive Response

This repository contains our group submission for the CSC3106 Cyber Security Fundamentals Mini Project.

The project analyses an assigned Linux authentication log using Python to identify suspicious authentication activity, generate reproducible evidence, assess cyber security risks, and evaluate a technical defensive response.

---

## Repository Structure

```text
CSC3106-MiniProject-GroupQ/
│
├── report/
│   └── report.pdf          # Final report
│
├── part1/                  # Authentication log analysis
│   ├── README.md
│   ├── analysis.py
│   ├── input/
│   └── output/
│
├── part2/                  # Technical defensive response
│   ├── README.md
│   ├── detect_and_respond.py
│   └── output/
│
├── requirements.txt
└── README.md
```

---

## Quick Start

1. Clone the repository.

```bash
git clone https://github.com/beansprout09/CSC3106-MiniProject-GroupQ.git
cd CSC3106-MiniProject-GroupQ
```

2. Install the required dependencies.

```bash
pip install -r requirements.txt
```

3. Place the assigned authentication log at:

```text
part1/input/4_auth.log
```

4. Run the Part 1 analysis.

```bash
python part1/analysis.py
```

For detailed documentation of each component, refer to the README files in `part1/` and `part2/`.

---

## Project Overview

### Part 1: Authentication Log Analysis

- Analyse the assigned Linux authentication log.
- Extract selected OpenSSH authentication events using Python.
- Generate reproducible evidence and visualisations.
- Identify security findings and prioritised risks.
- Assess risks to the chosen asset.

See **`part1/README.md`** for implementation details, assumptions, inputs, outputs, and limitations.

---

### Part 2: Technical Defensive Response

- Select one prioritised risk from Part 1.
- Design and implement a technical defensive response.
- Evaluate the effectiveness of the proposed control.
- Discuss security benefits, limitations, and trade-offs.

See **`part2/README.md`** for implementation details, execution instructions, parameters, outputs, and limitations.

---

## Requirements

- Python 3.10 or later
- Dependencies listed in `requirements.txt`

---

## Team Members

| Name | Responsibility |
|------|----------------|
| Haley & Daniel | Part 1:  Authentication Log Analysis |
| Chervelle & Jocasta | Part 2: Technical Defensive Response |
| All members | Report writing and documentation |

---

## License

This repository is provided for educational purposes as part of the CSC3106 Cyber Security Fundamentals module at the Singapore Institute of Technology and the University of Glasgow.