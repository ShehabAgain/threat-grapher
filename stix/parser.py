"""
STIX 2.1 parser for the bundled MITRE ATT&CK enterprise-attack.json.

Extracts techniques, tactics, data sources, data components, and their
relationships into a flat Python dict structure for use by the rest of
the application.
"""

import json
import os
import re


_STIX_PATH = os.path.join(os.path.dirname(__file__), 'enterprise-attack.json')


def load_stix_data(path=None):
    """Parse the STIX bundle and return an indexed dict.

    Returns
    -------
    dict with keys:
        techniques  – {mitre_id: {name, description, tactics, platforms, data_components, stix_id}}
        tactics     – {shortname: {name, external_id, stix_id}}
        data_sources – {name: {description, stix_id, components: [name, ...]}}
        data_components – {name: {data_source, stix_id, techniques: [mitre_id, ...]}}
        tactic_order – [shortname, ...] in ATT&CK matrix column order
    """
    path = path or _STIX_PATH
    with open(path, 'r', encoding='utf-8') as fh:
        bundle = json.load(fh)

    objects = bundle.get('objects', [])

    # ---- first pass: index raw objects by stix id ----
    by_id = {}
    techniques_raw = []
    tactics_raw = []
    data_sources_raw = []
    data_components_raw = []
    relationships = []

    for obj in objects:
        otype = obj.get('type', '')
        # skip revoked / deprecated objects
        if obj.get('revoked') or obj.get('x_mitre_deprecated'):
            continue
        by_id[obj['id']] = obj
        if otype == 'attack-pattern':
            techniques_raw.append(obj)
        elif otype == 'x-mitre-tactic':
            tactics_raw.append(obj)
        elif otype == 'x-mitre-data-source':
            data_sources_raw.append(obj)
        elif otype == 'x-mitre-data-component':
            data_components_raw.append(obj)
        elif otype == 'relationship':
            relationships.append(obj)

    # ---- tactics ----
    tactics = {}
    for t in tactics_raw:
        shortname = t.get('x_mitre_shortname', '')
        ext_id = _external_id(t)
        tactics[shortname] = {
            'name': t.get('name', ''),
            'external_id': ext_id,
            'stix_id': t['id'],
        }

    # ATT&CK enterprise tactic order
    tactic_order = [
        'reconnaissance', 'resource-development', 'initial-access',
        'execution', 'persistence', 'privilege-escalation',
        'defense-evasion', 'credential-access', 'discovery',
        'lateral-movement', 'collection', 'command-and-control',
        'exfiltration', 'impact',
    ]

    # ---- data sources & components ----
    data_sources = {}
    ds_id_to_name = {}
    for ds in data_sources_raw:
        name = ds.get('name', '')
        data_sources[name] = {
            'description': _first_para(ds.get('description', '')),
            'stix_id': ds['id'],
            'components': [],
        }
        ds_id_to_name[ds['id']] = name

    data_components = {}
    dc_id_to_name = {}
    for dc in data_components_raw:
        name = dc.get('name', '')
        # parent data source – try x_mitre_data_source_ref first, fall
        # back to relationship walk later
        parent_ref = dc.get('x_mitre_data_source_ref', '')
        parent_name = ds_id_to_name.get(parent_ref, '')
        data_components[name] = {
            'data_source': parent_name,
            'stix_id': dc['id'],
            'techniques': [],
        }
        dc_id_to_name[dc['id']] = name
        if parent_name and name not in data_sources.get(parent_name, {}).get('components', []):
            data_sources.setdefault(parent_name, {
                'description': '', 'stix_id': '', 'components': [],
            })['components'].append(name)

    # ---- techniques ----
    tech_id_map = {}  # stix_id -> mitre_id
    techniques = {}
    for t in techniques_raw:
        mitre_id = _external_id(t)
        if not mitre_id:
            continue
        tech_id_map[t['id']] = mitre_id
        phase_names = [p.get('phase_name', '') for p in t.get('kill_chain_phases', [])]
        techniques[mitre_id] = {
            'name': t.get('name', ''),
            'description': _first_para(t.get('description', '')),
            'tactics': phase_names,
            'platforms': t.get('x_mitre_platforms', []),
            'data_components': [],
            'stix_id': t['id'],
        }

    # ---- relationships ----
    subtechnique_parents = {}  # child_mitre_id -> parent_mitre_id
    for rel in relationships:
        if rel.get('revoked') or rel.get('x_mitre_deprecated'):
            continue
        rtype = rel.get('relationship_type', '')
        src = rel.get('source_ref', '')
        tgt = rel.get('target_ref', '')

        if rtype == 'detects':
            # data-component detects technique
            dc_name = dc_id_to_name.get(src, '')
            tech_mitre = tech_id_map.get(tgt, '')
            if dc_name and tech_mitre:
                if dc_name not in [d['component'] for d in techniques.get(tech_mitre, {}).get('data_components', [])]:
                    ds_name = data_components.get(dc_name, {}).get('data_source', '')
                    techniques.setdefault(tech_mitre, {}).setdefault('data_components', []).append({
                        'source': ds_name,
                        'component': dc_name,
                    })
                if tech_mitre not in data_components.get(dc_name, {}).get('techniques', []):
                    data_components.setdefault(dc_name, {}).setdefault('techniques', []).append(tech_mitre)

        elif rtype == 'subtechnique-of':
            child_id = tech_id_map.get(src, '')
            parent_id = tech_id_map.get(tgt, '')
            if child_id and parent_id:
                subtechnique_parents[child_id] = parent_id

    # backfill parent data source for data components missing x_mitre_data_source_ref
    for dc_name, dc_info in data_components.items():
        if not dc_info['data_source']:
            # try matching by name prefix  (e.g. "Process Creation" -> "Process")
            for ds_name in data_sources:
                if dc_name.startswith(ds_name):
                    dc_info['data_source'] = ds_name
                    data_sources[ds_name]['components'].append(dc_name)
                    break

    return {
        'techniques': techniques,
        'tactics': tactics,
        'tactic_order': tactic_order,
        'data_sources': data_sources,
        'data_components': data_components,
        'subtechnique_parents': subtechnique_parents,
    }


# ---- helpers ----

def _external_id(obj):
    """Extract the MITRE external ID (e.g. T1003.001) from external_references."""
    for ref in obj.get('external_references', []):
        eid = ref.get('external_id', '')
        if eid and re.match(r'^(T|TA)\d{4}', eid):
            return eid
    return ''


def _first_para(text):
    """Return the first paragraph (before double newline) of a description."""
    if not text:
        return ''
    idx = text.find('\n\n')
    if idx > 0:
        return text[:idx].strip()
    return text[:500].strip()
