import os
import re
import yaml
from pathlib import Path


TECHNIQUE_PATTERN = re.compile(r'^T\d{4}(?:\.\d{3})?$')
SUPPORTED_EXTENSIONS = {'.log', '.json'}
SKIP_EXTENSIONS = {'.yml', '.yaml', '.zip', '.gz', '.raw'}


def natural_sort_key(s):
    parts = re.split(r'(\d+)', s)
    return [int(p) if p.isdigit() else p.lower() for p in parts]


def scan_techniques(data_dir):
    """Scan attack_techniques/ and build a structured technique tree.

    Returns a dict with two keys:
      - 'techniques': ordered dict of technique_id -> technique_data
      - 'grouped': ordered dict of parent_id -> list of sub-technique ids
    """
    data_path = Path(data_dir)
    if not data_path.exists():
        return {'techniques': {}, 'grouped': {}}

    raw = {}

    for entry in data_path.iterdir():
        if not entry.is_dir():
            continue
        if not TECHNIQUE_PATTERN.match(entry.name):
            continue

        technique_id = entry.name
        technique_data = _scan_technique_dir(entry, technique_id)
        raw[technique_id] = technique_data

    sorted_ids = sorted(raw.keys(), key=natural_sort_key)
    techniques = {tid: raw[tid] for tid in sorted_ids}

    grouped = {}
    for tid in sorted_ids:
        if '.' in tid:
            parent = tid.split('.')[0]
        else:
            parent = tid
        if parent not in grouped:
            grouped[parent] = []
        if tid != parent:
            grouped[parent].append(tid)

    for parent in list(grouped.keys()):
        if parent not in techniques:
            techniques[parent] = {
                'id': parent,
                'yml_path': None,
                'yml_data': {},
                'files': [],
                'scenarios': {},
            }

    return {'techniques': techniques, 'grouped': grouped}


def _scan_technique_dir(dir_path, technique_id):
    result = {
        'id': technique_id,
        'yml_path': None,
        'yml_data': {},
        'files': [],
        'scenarios': {},
    }

    for item in dir_path.iterdir():
        if item.is_file():
            ext = item.suffix.lower()
            if ext in ('.yml', '.yaml'):
                result['yml_path'] = str(item)
                result['yml_data'] = _load_yaml(item)
            elif ext in SUPPORTED_EXTENSIONS:
                result['files'].append({
                    'name': item.name,
                    'path': str(item),
                    'size': item.stat().st_size,
                })
        elif item.is_dir():
            scenario = _scan_scenario_dir(item)
            result['scenarios'][item.name] = scenario

    result['files'].sort(key=lambda f: f['name'])
    return result


def _scan_scenario_dir(dir_path):
    scenario = {
        'yml_path': None,
        'yml_data': {},
        'files': [],
    }

    for item in dir_path.iterdir():
        if item.is_file():
            ext = item.suffix.lower()
            if ext in ('.yml', '.yaml'):
                scenario['yml_path'] = str(item)
                scenario['yml_data'] = _load_yaml(item)
            elif ext in SUPPORTED_EXTENSIONS:
                scenario['files'].append({
                    'name': item.name,
                    'path': str(item),
                    'size': item.stat().st_size,
                })
        elif item.is_dir():
            for nested in item.rglob('*'):
                if nested.is_file():
                    ext = nested.suffix.lower()
                    if ext in ('.yml', '.yaml') and not scenario['yml_path']:
                        scenario['yml_path'] = str(nested)
                        scenario['yml_data'] = _load_yaml(nested)
                    elif ext in SUPPORTED_EXTENSIONS:
                        scenario['files'].append({
                            'name': nested.name,
                            'path': str(nested),
                            'size': nested.stat().st_size,
                        })

    scenario['files'].sort(key=lambda f: f['name'])
    return scenario


def _load_yaml(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}
