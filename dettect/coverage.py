"""
Dataset coverage analyzer.

Scans the technique tree's log files to determine which MITRE ATT&CK
data components are actually present in the dataset, then cross-references
with STIX technique requirements to calculate per-technique coverage.
"""

import os
import re
import random
from collections import Counter

from dettect.mappings import EVENT_TO_DATA_COMPONENT, SOURCETYPE_TO_FORMAT


def analyze_coverage(technique_tree, stix_data):
    """Scan dataset files and calculate coverage against STIX requirements.

    Parameters
    ----------
    technique_tree : dict from scan_techniques()
    stix_data : dict from load_stix_data()

    Returns
    -------
    dict with keys:
        detected_components – {component_name: {count, sources: [str]}}
        technique_coverage  – {mitre_id: {required, covered, missing, coverage_pct}}
        overall_coverage_pct – float
    """
    techniques = technique_tree.get('techniques', {})

    # ---- phase 1: collect all log files with metadata ----
    file_records = []
    for tid, tdata in techniques.items():
        yml = tdata.get('yml_data', {})
        for f in tdata.get('files', []):
            file_records.append({
                'path': f['path'],
                'technique_id': tid,
                'sourcetype': _get_sourcetype_from_yml(yml, f['name']),
            })
        for sname, sdata in tdata.get('scenarios', {}).items():
            syml = sdata.get('yml_data', {})
            for f in sdata.get('files', []):
                file_records.append({
                    'path': f['path'],
                    'technique_id': tid,
                    'sourcetype': _get_sourcetype_from_yml(syml, f['name']),
                })

    # ---- phase 2: sample log files and extract event IDs ----
    log_records = [r for r in file_records if r['path'].endswith('.log')]
    sample_size = min(200, len(log_records))
    sampled = random.sample(log_records, sample_size) if log_records else []

    xml_eid_re = re.compile(r'<EventID[^>]*>(\d+)</EventID>')
    kv_eid_re = re.compile(r'^EventCode=(\d+)', re.MULTILINE)

    # component_name -> {count, source_labels}
    detected = {}

    for rec in sampled:
        try:
            size = os.path.getsize(rec['path'])
            read_limit = min(size, 512 * 1024)
            with open(rec['path'], 'r', encoding='utf-8', errors='replace') as fh:
                chunk = fh.read(read_limit)
        except Exception:
            continue

        fmt = None
        event_ids = []

        # detect format
        xml_ids = xml_eid_re.findall(chunk)
        if xml_ids:
            fmt = 'xml_sysmon'
            event_ids = xml_ids
        else:
            kv_ids = kv_eid_re.findall(chunk)
            if kv_ids:
                fmt = 'keyvalue'
                event_ids = kv_ids
            elif chunk.lstrip().startswith('{'):
                fmt = 'json'

        if not fmt:
            continue

        if fmt == 'json':
            # for JSON, try to detect CloudTrail-style events
            _detect_json_components(chunk, detected)
            continue

        counts = Counter(event_ids)
        for eid, cnt in counts.items():
            key = (fmt, eid)
            mapping = EVENT_TO_DATA_COMPONENT.get(key)
            if mapping:
                ds, dc = mapping
                label = f'{_format_label(fmt)} EID {eid}'
                if dc not in detected:
                    detected[dc] = {'count': 0, 'sources': set()}
                detected[dc]['count'] += cnt
                detected[dc]['sources'].add(label)

    # also scan JSON files
    json_records = [r for r in file_records if r['path'].endswith('.json')]
    json_sample = random.sample(json_records, min(50, len(json_records))) if json_records else []
    for rec in json_sample:
        try:
            size = os.path.getsize(rec['path'])
            read_limit = min(size, 256 * 1024)
            with open(rec['path'], 'r', encoding='utf-8', errors='replace') as fh:
                chunk = fh.read(read_limit)
            _detect_json_components(chunk, detected)
        except Exception:
            continue

    # convert source sets to sorted lists
    for dc_name in detected:
        detected[dc_name]['sources'] = sorted(detected[dc_name]['sources'])

    # ---- phase 3: calculate per-technique coverage ----
    stix_techniques = stix_data.get('techniques', {})
    technique_coverage = {}
    covered_count = 0
    total_with_reqs = 0

    for mitre_id, sdata in stix_techniques.items():
        required_components = [d['component'] for d in sdata.get('data_components', [])]
        if not required_components:
            continue

        total_with_reqs += 1
        covered = [c for c in required_components if c in detected]
        missing = [c for c in required_components if c not in detected]
        pct = (len(covered) / len(required_components)) * 100 if required_components else 0

        technique_coverage[mitre_id] = {
            'name': sdata.get('name', ''),
            'tactics': sdata.get('tactics', []),
            'required': required_components,
            'covered': covered,
            'missing': missing,
            'coverage_pct': round(pct, 1),
        }
        if pct > 0:
            covered_count += 1

    overall_pct = (covered_count / total_with_reqs * 100) if total_with_reqs else 0

    return {
        'detected_components': detected,
        'technique_coverage': technique_coverage,
        'overall_coverage_pct': round(overall_pct, 1),
        'techniques_with_data': covered_count,
        'techniques_with_requirements': total_with_reqs,
    }


def _detect_json_components(chunk, detected):
    """Detect MITRE data components from JSON log content."""
    import json as _json

    # try to find CloudTrail-style events
    patterns = {
        'eventName': None,
        'eventSource': None,
    }
    for line in chunk.split('\n')[:50]:
        line = line.strip().rstrip(',')
        if not line:
            continue
        for key in patterns:
            if f'"{key}"' in line:
                # rough extraction
                match = re.search(rf'"{key}"\s*:\s*"([^"]+)"', line)
                if match:
                    patterns[key] = match.group(1)

    event_name = patterns['eventName']
    if event_name:
        key = ('json', event_name)
        mapping = EVENT_TO_DATA_COMPONENT.get(key)
        if mapping:
            ds, dc = mapping
            label = f'CloudTrail {event_name}'
            if dc not in detected:
                detected[dc] = {'count': 0, 'sources': set()}
            detected[dc]['count'] += 1
            detected[dc]['sources'].add(label)
        else:
            # generic cloud service
            dc = 'Cloud Service Enumeration'
            if dc not in detected:
                detected[dc] = {'count': 0, 'sources': set()}
            detected[dc]['count'] += 1
            detected[dc]['sources'].add(f'CloudTrail {event_name}')


def _get_sourcetype_from_yml(yml_data, filename):
    """Extract sourcetype hint from YAML metadata for a given file."""
    datasets = yml_data.get('datasets', [])
    if not datasets:
        return ''
    for ds in datasets:
        if not isinstance(ds, dict):
            continue
        ds_name = ds.get('name', '')
        if ds_name and ds_name in filename:
            return ds.get('sourcetype', '')
    return ''


def _format_label(fmt):
    """Human label for a log format."""
    return {
        'xml_sysmon': 'Sysmon',
        'keyvalue': 'WinSecurity',
        'json': 'JSON',
    }.get(fmt, fmt)
