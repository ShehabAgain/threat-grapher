import os
import sys

# Ensure the MVP directory is on the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dash
import dash_bootstrap_components as dbc

from data.scanner import scan_techniques
from data.stats import compute_dataset_stats
from stix.parser import load_stix_data
from dettect.coverage import analyze_coverage
from dettect.visibility import calculate_visibility
from dettect.yaml_admin import (
    load_data_sources_admin, save_data_sources_admin, generate_data_sources_admin,
    load_technique_admin, save_technique_admin, generate_technique_admin,
    DS_ADMIN_PATH, TECH_ADMIN_PATH,
)
from ui.layout import create_layout
from ui.callbacks import register_callbacks
from ui.coverage_callbacks import register_coverage_callbacks


DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'attack_techniques')
MAX_EVENTS = 2000


def create_app():
    print('Scanning attack techniques directory...')
    technique_tree = scan_techniques(DATA_DIR)

    tech_count = len(technique_tree.get('techniques', {}))
    group_count = len(technique_tree.get('grouped', {}))
    print(f'Found {tech_count} techniques in {group_count} groups.')

    print('Computing dataset statistics...')
    dataset_stats = compute_dataset_stats(technique_tree)
    print(f'Sampled {dataset_stats["sampled_files"]} files, found {dataset_stats["sample_event_count"]} events.')

    # ---- STIX + DeTT&CT coverage pipeline ----
    print('Loading MITRE ATT&CK STIX data...')
    stix_data = load_stix_data()
    print(f'  {len(stix_data["techniques"])} techniques, {len(stix_data["tactics"])} tactics, '
          f'{len(stix_data["data_components"])} data components')

    print('Analyzing dataset coverage...')
    coverage_result = analyze_coverage(technique_tree, stix_data)
    print(f'  {len(coverage_result["detected_components"])} data components detected, '
          f'{coverage_result["overall_coverage_pct"]}% technique coverage')

    # Load or auto-generate DeTT&CT YAML admin files
    ds_admin = load_data_sources_admin()
    if not ds_admin:
        print('Auto-generating data sources administration YAML...')
        ds_admin = generate_data_sources_admin(coverage_result)
        save_data_sources_admin(ds_admin)

    tech_admin = load_technique_admin()
    if not tech_admin:
        print('Auto-generating technique administration YAML...')
        tech_admin = generate_technique_admin(stix_data, coverage_result)
        save_technique_admin(tech_admin)

    print('Calculating visibility scores...')
    visibility = calculate_visibility(stix_data, coverage_result, ds_admin)
    print(f'  Overall visibility score: {visibility["overall_score"]}/5')

    app = dash.Dash(
        __name__,
        external_stylesheets=[dbc.themes.DARKLY],
        suppress_callback_exceptions=True,
        title='ThreatGrapher - MITRE ATT&CK Visualizer',
    )

    app.layout = create_layout(technique_tree, dataset_stats, stix_data, visibility)
    register_callbacks(app, technique_tree, DATA_DIR, MAX_EVENTS, stix_data, visibility)
    register_coverage_callbacks(app, stix_data, coverage_result, visibility, ds_admin)

    return app


if __name__ == '__main__':
    app = create_app()
    print('Starting ThreatGrapher on http://127.0.0.1:8050')
    app.run(debug=True, host='127.0.0.1', port=8050)
