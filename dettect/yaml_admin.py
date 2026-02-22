"""
DeTT&CT-compatible YAML administration file reader/writer.

Handles two file types:
  - data_sources_admin.yml  (data source quality scores)
  - technique_admin.yml     (technique visibility/detection scores)

Follows the DeTT&CT YAML schema so files can also be consumed by the
standalone DeTT&CT tool.
"""

import os
from datetime import date

import yaml


_COVERAGE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'coverage',
)

DS_ADMIN_PATH = os.path.join(_COVERAGE_DIR, 'data_sources_admin.yml')
TECH_ADMIN_PATH = os.path.join(_COVERAGE_DIR, 'technique_admin.yml')


# ---- data sources ----

def load_data_sources_admin(path=None):
    """Load data source quality scores from YAML. Returns dict keyed by component name."""
    path = path or DS_ADMIN_PATH
    if not os.path.isfile(path):
        return {}
    with open(path, 'r', encoding='utf-8') as fh:
        raw = yaml.safe_load(fh) or {}
    result = {}
    for ds in raw.get('data_sources', []):
        name = ds.get('data_source_name', '')
        if name:
            result[name] = ds
    return result


def save_data_sources_admin(data_sources_dict, path=None):
    """Write data source quality scores to YAML.

    Parameters
    ----------
    data_sources_dict : dict  {component_name: {data_quality: {...}, products: [...], ...}}
    """
    path = path or DS_ADMIN_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)

    entries = []
    for name, info in sorted(data_sources_dict.items()):
        entry = {
            'data_source_name': name,
            'date_registered': info.get('date_registered', str(date.today())),
            'date_connected': info.get('date_connected', str(date.today())),
            'available_for_data_analytics': info.get('available_for_data_analytics', True),
            'products': info.get('products', []),
            'comment': info.get('comment', ''),
            'data_quality': info.get('data_quality', _default_quality()),
        }
        entries.append(entry)

    doc = {
        'version': 1,
        'file_type': 'data-source-administration',
        'data_sources': entries,
    }

    with open(path, 'w', encoding='utf-8') as fh:
        yaml.dump(doc, fh, default_flow_style=False, sort_keys=False, allow_unicode=True)


def generate_data_sources_admin(coverage_result):
    """Auto-generate a data sources admin dict from coverage analysis results.

    Parameters
    ----------
    coverage_result : dict from analyze_coverage()

    Returns
    -------
    dict keyed by component name, ready to be passed to save_data_sources_admin()
    """
    detected = coverage_result.get('detected_components', {})
    result = {}
    today = str(date.today())
    for dc_name, info in detected.items():
        result[dc_name] = {
            'date_registered': today,
            'date_connected': today,
            'available_for_data_analytics': True,
            'products': list(info.get('sources', [])),
            'comment': f'Auto-detected from dataset ({info.get("count", 0)} events)',
            'data_quality': _default_quality(),
        }
    return result


# ---- techniques ----

def load_technique_admin(path=None):
    """Load technique visibility/detection scores from YAML. Returns dict keyed by technique_id."""
    path = path or TECH_ADMIN_PATH
    if not os.path.isfile(path):
        return {}
    with open(path, 'r', encoding='utf-8') as fh:
        raw = yaml.safe_load(fh) or {}
    result = {}
    for t in raw.get('techniques', []):
        tid = t.get('technique_id', '')
        if tid:
            result[tid] = t
    return result


def save_technique_admin(technique_dict, path=None):
    """Write technique visibility/detection scores to YAML."""
    path = path or TECH_ADMIN_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)

    entries = []
    for tid, info in sorted(technique_dict.items()):
        vis = info.get('visibility', {})
        det = info.get('detection', {})
        entry = {
            'technique_id': tid,
            'technique_name': info.get('technique_name', ''),
            'visibility': {
                'score': vis.get('score', 0),
                'comment': vis.get('comment', ''),
            },
            'detection': {
                'score': det.get('score', 0),
                'comment': det.get('comment', ''),
            },
        }
        entries.append(entry)

    doc = {
        'version': 1,
        'file_type': 'technique-administration',
        'techniques': entries,
    }

    with open(path, 'w', encoding='utf-8') as fh:
        yaml.dump(doc, fh, default_flow_style=False, sort_keys=False, allow_unicode=True)


def generate_technique_admin(stix_data, coverage_result):
    """Auto-generate technique admin dict from STIX + coverage.

    Parameters
    ----------
    stix_data : dict from load_stix_data()
    coverage_result : dict from analyze_coverage()

    Returns
    -------
    dict keyed by technique_id
    """
    tech_coverage = coverage_result.get('technique_coverage', {})
    stix_techniques = stix_data.get('techniques', {})
    result = {}
    for tid, sinfo in stix_techniques.items():
        cov = tech_coverage.get(tid, {})
        pct = cov.get('coverage_pct', 0)
        result[tid] = {
            'technique_name': sinfo.get('name', ''),
            'visibility': {
                'score': 0,
                'comment': f'Auto: {pct}% data component coverage' if pct > 0 else '',
            },
            'detection': {
                'score': 0,
                'comment': '',
            },
        }
    return result


def _default_quality():
    return {
        'device_completeness': 0,
        'data_field_completeness': 0,
        'timeliness': 0,
        'consistency': 0,
        'retention': 0,
    }
