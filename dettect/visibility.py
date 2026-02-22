"""
Visibility score engine.

Calculates per-technique visibility scores (0-5) based on:
  1. STIX-defined required data components per technique
  2. Which data components are actually present in the dataset
  3. DeTT&CT data quality scores from the YAML admin files
"""


def calculate_visibility(stix_data, coverage_result, ds_admin):
    """Calculate visibility scores for all techniques.

    Parameters
    ----------
    stix_data : dict from load_stix_data()
    coverage_result : dict from analyze_coverage()
    ds_admin : dict from load_data_sources_admin()  {component_name: {..., data_quality: {...}}}

    Returns
    -------
    dict with keys:
        technique_scores – {mitre_id: {score, coverage_pct, quality_avg, details}}
        tactic_summary   – {tactic_shortname: {avg_score, count, covered, gaps}}
        overall_score    – float (0-5)
    """
    stix_techniques = stix_data.get('techniques', {})
    detected = coverage_result.get('detected_components', {})
    tech_coverage = coverage_result.get('technique_coverage', {})

    technique_scores = {}

    for mitre_id, sinfo in stix_techniques.items():
        required = [d['component'] for d in sinfo.get('data_components', [])]
        if not required:
            technique_scores[mitre_id] = {
                'name': sinfo.get('name', ''),
                'tactics': sinfo.get('tactics', []),
                'score': 0,
                'coverage_pct': 0,
                'quality_avg': 0,
                'required_count': 0,
                'covered_count': 0,
                'missing': [],
                'covered': [],
            }
            continue

        covered = [c for c in required if c in detected]
        missing = [c for c in required if c not in detected]
        cov_pct = len(covered) / len(required) * 100

        # average data quality of covered components
        quality_scores = []
        for comp_name in covered:
            admin = ds_admin.get(comp_name, {})
            dq = admin.get('data_quality', {})
            if dq:
                dims = [
                    dq.get('device_completeness', 0),
                    dq.get('data_field_completeness', 0),
                    dq.get('timeliness', 0),
                    dq.get('consistency', 0),
                    dq.get('retention', 0),
                ]
                quality_scores.append(sum(dims) / len(dims))

        quality_avg = sum(quality_scores) / len(quality_scores) if quality_scores else 0

        score = _compute_score(cov_pct, quality_avg)

        technique_scores[mitre_id] = {
            'name': sinfo.get('name', ''),
            'tactics': sinfo.get('tactics', []),
            'score': score,
            'coverage_pct': round(cov_pct, 1),
            'quality_avg': round(quality_avg, 2),
            'required_count': len(required),
            'covered_count': len(covered),
            'missing': missing,
            'covered': covered,
        }

    # ---- tactic summary ----
    tactic_summary = {}
    for mitre_id, tinfo in technique_scores.items():
        for tactic in tinfo.get('tactics', []):
            if tactic not in tactic_summary:
                tactic_summary[tactic] = {
                    'scores': [],
                    'count': 0,
                    'covered': 0,
                    'gaps': 0,
                }
            tactic_summary[tactic]['count'] += 1
            tactic_summary[tactic]['scores'].append(tinfo['score'])
            if tinfo['score'] > 0:
                tactic_summary[tactic]['covered'] += 1
            else:
                tactic_summary[tactic]['gaps'] += 1

    for tactic, summary in tactic_summary.items():
        scores = summary.pop('scores')
        summary['avg_score'] = round(sum(scores) / len(scores), 2) if scores else 0

    # ---- overall ----
    all_scores = [t['score'] for t in technique_scores.values()]
    overall = round(sum(all_scores) / len(all_scores), 2) if all_scores else 0

    return {
        'technique_scores': technique_scores,
        'tactic_summary': tactic_summary,
        'overall_score': overall,
    }


def _compute_score(coverage_pct, quality_avg):
    """Map coverage percentage and quality average to a 0-5 score.

    Scoring logic:
        - 0: no data components covered at all
        - 1: some coverage (<25%) or coverage with zero quality scores
        - 2: 25-50% coverage
        - 3: 50-75% coverage
        - 4: 75-100% coverage with moderate quality (avg >= 2)
        - 5: full coverage with high quality (avg >= 3.5)
    """
    if coverage_pct <= 0:
        return 0

    # base score from coverage
    if coverage_pct < 25:
        base = 1
    elif coverage_pct < 50:
        base = 2
    elif coverage_pct < 75:
        base = 3
    elif coverage_pct < 100:
        base = 4
    else:
        base = 4

    # quality boost: can push from 4 to 5 if quality is high
    if coverage_pct >= 75 and quality_avg >= 3.5:
        return 5
    if coverage_pct >= 75 and quality_avg >= 2:
        return 4

    # quality can't push below base, but zero quality caps at base
    return base


def generate_navigator_layer(technique_scores, name='ThreatGrapher Visibility'):
    """Generate an ATT&CK Navigator layer JSON from visibility scores.

    Parameters
    ----------
    technique_scores : dict {mitre_id: {score, ...}}
    name : str

    Returns
    -------
    dict  (ATT&CK Navigator layer JSON structure)
    """
    # score -> color mapping (red to green gradient)
    score_colors = {
        0: '#d13b31',   # red
        1: '#e57339',   # orange-red
        2: '#e5a839',   # orange
        3: '#e5d439',   # yellow
        4: '#7bc043',   # light green
        5: '#2d8a4e',   # green
    }

    techniques_layer = []
    for mitre_id, info in technique_scores.items():
        score = info.get('score', 0)
        techniques_layer.append({
            'techniqueID': mitre_id,
            'score': score,
            'color': score_colors.get(score, '#d13b31'),
            'comment': f"Coverage: {info.get('coverage_pct', 0)}% | "
                       f"Quality: {info.get('quality_avg', 0)} | "
                       f"Covered: {info.get('covered_count', 0)}/{info.get('required_count', 0)}",
            'enabled': True,
        })

    layer = {
        'name': name,
        'versions': {
            'attack': '16',
            'navigator': '5.1',
            'layer': '4.5',
        },
        'domain': 'enterprise-attack',
        'description': f'Visibility coverage layer generated by ThreatGrapher',
        'sorting': 3,
        'layout': {
            'layout': 'side',
            'aggregateFunction': 'average',
            'showID': True,
            'showName': True,
            'showAggregateScores': True,
            'countUnscored': False,
        },
        'gradient': {
            'colors': ['#d13b31', '#e5a839', '#2d8a4e'],
            'minValue': 0,
            'maxValue': 5,
        },
        'techniques': techniques_layer,
    }

    return layer
