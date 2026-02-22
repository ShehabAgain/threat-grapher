# ThreatGrapher

MITRE ATT&CK threat intelligence visualizer and coverage dashboard. Parses security log datasets (Splunk Attack Data format), maps them to MITRE ATT&CK techniques, and provides interactive graph visualizations and DeTT&CT-style visibility scoring.

## Features

- **Technique Browser** -- Sidebar navigation of ATT&CK technique directories with YAML metadata parsing
- **Log Parsing** -- Handles Sysmon XML, Windows Security XML, key-value, JSON, CSV, and NDJSON log formats
- **Graph Visualization** -- NetworkX-based entity relationship graphs rendered as interactive Plotly figures (processes, network connections, registry, files)
- **Event Table** -- Sortable/filterable data table of parsed log events
- **STIX Integration** -- Bundled MITRE ATT&CK STIX 2.1 data (v15.1) mapping techniques to tactics, data sources, and data components
- **Coverage Analysis** -- Automated detection of which MITRE data components are present in the dataset based on EventID mapping
- **Visibility Scoring** -- DeTT&CT-style 0-5 visibility scores per technique based on data component coverage and data quality ratings
- **ATT&CK Heatmap** -- Color-coded heatmap of technique visibility scores grouped by tactic
- **Gap Analysis** -- Table of techniques with zero visibility, showing missing data components
- **Navigator Export** -- Export visibility scores as an ATT&CK Navigator layer JSON file
- **DeTT&CT YAML Persistence** -- Auto-generated data source and technique administration YAML files with editable quality scores

## Project Structure

```
MVP/
├── app.py                          # Application entry point
├── requirements.txt                # Python dependencies
├── assets/
│   └── styles.css                  # Custom CSS (dark theme)
├── data/
│   ├── scanner.py                  # Dataset directory scanner
│   ├── loader.py                   # Log file loader/parser
│   └── stats.py                    # Dataset statistics computation
├── parsers/
│   ├── xml_parser.py               # Sysmon/Security XML parser
│   ├── kv_parser.py                # Key-value format parser
│   ├── json_parser.py              # JSON/NDJSON parser
│   └── csv_parser.py               # CSV parser
├── graph/
│   └── builder.py                  # NetworkX graph construction + Plotly rendering
├── stix/
│   ├── parser.py                   # STIX 2.1 bundle parser
│   └── enterprise-attack.json      # MITRE ATT&CK STIX data (not in repo, see Setup)
├── dettect/
│   ├── mappings.py                 # EventID -> MITRE Data Component mapping table
│   ├── coverage.py                 # Dataset coverage analyzer
│   ├── visibility.py               # Visibility score engine + Navigator export
│   └── yaml_admin.py               # DeTT&CT YAML file read/write
├── coverage/                       # Auto-generated on first run
│   ├── data_sources_admin.yml      # Data source quality scores
│   └── technique_admin.yml         # Technique visibility/detection scores
└── ui/
    ├── layout.py                   # Main Dash layout
    ├── callbacks.py                # Core UI callbacks
    ├── coverage_layout.py          # Coverage dashboard UI components
    ├── coverage_callbacks.py       # Coverage dashboard callbacks
    └── styles.py                   # Style constants
```

## Setup

### Prerequisites

- Python 3.10+
- The Splunk Attack Data dataset (placed in `attack_techniques/`)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/ShehabAgain/ThreatGrapher.git
   cd ThreatGrapher/MVP
   ```

2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   venv\Scripts\activate     # Windows
   pip install -r requirements.txt
   ```

3. Download the MITRE ATT&CK STIX data:
   ```bash
   curl -L -o stix/enterprise-attack.json \
     "https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v15.1/enterprise-attack/enterprise-attack.json"
   ```
   Or with PowerShell:
   ```powershell
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v15.1/enterprise-attack/enterprise-attack.json" -OutFile "stix\enterprise-attack.json"
   ```

4. Place the Splunk Attack Data dataset in `attack_techniques/`. The expected structure is:
   ```
   attack_techniques/
   ├── T1003.001/
   │   ├── scenario_name/
   │   │   ├── logfile.xml
   │   │   └── metadata.yml
   │   └── ...
   ├── T1059/
   └── ...
   ```

### Running

```bash
python app.py
```

Open `http://127.0.0.1:8050` in your browser.

## Usage

### Technique Browser

Select techniques from the left sidebar to view:
- STIX-enriched metadata (description, tactics, data component coverage)
- Parsed log files rendered as entity-relationship graphs
- Sortable/filterable event data tables

### Coverage Dashboard

Click the **Coverage** toggle in the navbar to view:
- **Visibility Overview** -- Aggregate stats (overall score, technique counts, gap count)
- **Tactic Bars** -- Per-tactic average visibility scores
- **Visibility Heatmap** -- ATT&CK-style matrix colored by score (red = 0, green = 5)
- **Detected Data Components** -- Table of data components found in the dataset
- **Gap Analysis** -- Techniques with zero visibility and their missing data components
- **Export Navigator Layer** -- Download an ATT&CK Navigator JSON for external visualization

### Visibility Scoring

Scores are calculated on a 0-5 scale based on:

| Score | Criteria |
|-------|----------|
| 0 | No required data components covered |
| 1 | < 25% coverage |
| 2 | 25-50% coverage |
| 3 | 50-75% coverage |
| 4 | 75-100% coverage with quality avg >= 2 |
| 5 | Full coverage with quality avg >= 3.5 |

Data quality is scored across 5 DeTT&CT dimensions (0-5 each): device completeness, data field completeness, timeliness, consistency, and retention. Edit these in `coverage/data_sources_admin.yml`.

## Technical Notes

- **STIX Version**: Uses ATT&CK v15.1 (not v18) for DeTT&CT compatibility. v15.1 has direct `x-mitre-data-component` objects with `detects` relationships to techniques.
- **Max Events**: Files are sampled to 2,000 events by default to keep the UI responsive. Configurable via `MAX_EVENTS` in `app.py`.
- **Log Format Detection**: Automatic format detection with heuristic cascading (XML -> JSON -> key-value -> CSV).
- **No External Database**: All data is held in-memory (NetworkX graphs, Python dicts). YAML files provide persistence for scoring.

## License

MIT
