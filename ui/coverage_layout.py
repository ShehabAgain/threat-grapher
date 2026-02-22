"""
Coverage dashboard UI components.

Provides the ATT&CK visibility heatmap, data source quality table,
and coverage statistics panels.
"""

from dash import html, dcc, dash_table
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
from ui.styles import CARD_STYLE


def build_coverage_tab(stix_data, visibility):
    """Build the coverage dashboard tab content."""
    return html.Div([
        _build_coverage_stats(visibility),
        html.Br(),
        _build_heatmap(stix_data, visibility),
        html.Br(),
        _build_data_sources_table(visibility),
        html.Br(),
        _build_gap_analysis(visibility),
    ])


def _build_coverage_stats(visibility):
    """Top-level coverage statistics bar."""
    tech_scores = visibility.get('technique_scores', {})
    overall = visibility.get('overall_score', 0)
    tactic_summary = visibility.get('tactic_summary', {})

    total = len(tech_scores)
    covered = sum(1 for t in tech_scores.values() if t['score'] > 0)
    gaps = total - covered
    high_vis = sum(1 for t in tech_scores.values() if t['score'] >= 4)

    def _stat(label, value, color='#3498db'):
        return html.Div([
            html.Div(str(value), style={
                'fontSize': '28px', 'fontWeight': '700', 'color': color,
                'fontFamily': "'Share Tech Mono', monospace", 'lineHeight': '1',
            }),
            html.Div(label, style={
                'fontSize': '9px', 'letterSpacing': '2px', 'color': '#555',
                'marginTop': '4px', 'textTransform': 'uppercase',
                'fontFamily': "'Share Tech Mono', monospace",
            }),
        ], style={'textAlign': 'center', 'padding': '12px 8px', 'flex': '1'})

    return html.Div([
        html.Div('VISIBILITY OVERVIEW', style={
            'fontSize': '10px', 'letterSpacing': '3px', 'color': '#555',
            'marginBottom': '8px', 'fontFamily': "'Share Tech Mono', monospace",
        }),
        html.Div([
            html.Div([
                _stat('OVERALL SCORE', f'{overall}/5', _score_color(overall)),
                _stat('TECHNIQUES', total, '#3498db'),
                _stat('WITH DATA', covered, '#2ecc71'),
                _stat('GAPS', gaps, '#e74c3c'),
                _stat('HIGH VIS (4+)', high_vis, '#f39c12'),
            ], style={
                'display': 'flex', 'justifyContent': 'space-around',
                'paddingBottom': '10px', 'marginBottom': '10px',
                'borderBottom': '1px solid #1a1a2e',
            }),
            _build_tactic_bars(tactic_summary, stix_data=None),
        ], style={
            'backgroundColor': 'rgba(15, 15, 35, 0.6)',
            'border': '1px solid #1a1a2e', 'borderRadius': '4px',
            'padding': '12px 15px',
        }),
    ], className='glow-card')


def _build_tactic_bars(tactic_summary, stix_data=None):
    """Horizontal bar for each tactic showing avg visibility score."""
    tactic_order = [
        'reconnaissance', 'resource-development', 'initial-access',
        'execution', 'persistence', 'privilege-escalation',
        'defense-evasion', 'credential-access', 'discovery',
        'lateral-movement', 'collection', 'command-and-control',
        'exfiltration', 'impact',
    ]
    rows = []
    for tactic in tactic_order:
        info = tactic_summary.get(tactic, {})
        avg = info.get('avg_score', 0)
        count = info.get('count', 0)
        if count == 0:
            continue
        pct = min(avg / 5 * 100, 100)
        label = tactic.replace('-', ' ').title()
        rows.append(html.Div([
            html.Div(label, style={
                'width': '180px', 'fontSize': '11px', 'color': '#b0b0b0',
                'fontFamily': "'Share Tech Mono', monospace",
                'flexShrink': '0',
            }),
            html.Div([
                html.Div(style={
                    'width': f'{pct}%', 'height': '14px',
                    'backgroundColor': _score_color(avg),
                    'borderRadius': '2px', 'transition': 'width 0.5s',
                }),
            ], style={
                'flex': '1', 'backgroundColor': '#0a0a1a',
                'borderRadius': '2px', 'marginRight': '10px',
            }),
            html.Span(f'{avg:.1f}', style={
                'fontSize': '11px', 'color': _score_color(avg), 'width': '30px',
                'fontFamily': "'Share Tech Mono', monospace",
            }),
            html.Span(f'({count})', style={
                'fontSize': '10px', 'color': '#555', 'width': '40px',
                'fontFamily': "'Share Tech Mono', monospace",
            }),
        ], style={'display': 'flex', 'alignItems': 'center', 'marginBottom': '3px'}))

    return html.Div(rows)


def _build_heatmap(stix_data, visibility):
    """ATT&CK-style heatmap colored by visibility score."""
    tech_scores = visibility.get('technique_scores', {})
    tactic_order = stix_data.get('tactic_order', [])
    tactics = stix_data.get('tactics', {})

    # group techniques by tactic
    tactic_techs = {t: [] for t in tactic_order}
    for mitre_id, info in tech_scores.items():
        for tactic in info.get('tactics', []):
            if tactic in tactic_techs:
                tactic_techs[tactic].append((mitre_id, info))

    # sort each column by score descending
    for tactic in tactic_techs:
        tactic_techs[tactic].sort(key=lambda x: (-x[1]['score'], x[0]))

    max_rows = max((len(v) for v in tactic_techs.values()), default=0)

    # build Plotly heatmap
    z = []
    hover_text = []
    y_labels = list(range(max_rows))
    x_labels = []

    for tactic in tactic_order:
        tname = tactics.get(tactic, {}).get('name', tactic.replace('-', ' ').title())
        x_labels.append(tname)

    z_matrix = []
    text_matrix = []
    customdata = []

    for row_idx in range(max_rows):
        z_row = []
        text_row = []
        cd_row = []
        for tactic in tactic_order:
            techs = tactic_techs.get(tactic, [])
            if row_idx < len(techs):
                tid, info = techs[row_idx]
                score = info['score']
                z_row.append(score)
                text_row.append(
                    f"<b>{tid}</b> - {info.get('name', '')}<br>"
                    f"Score: {score}/5<br>"
                    f"Coverage: {info.get('coverage_pct', 0)}%<br>"
                    f"Covered: {info.get('covered_count', 0)}/{info.get('required_count', 0)}"
                )
                cd_row.append(tid)
            else:
                z_row.append(None)
                text_row.append('')
                cd_row.append('')
        z_matrix.append(z_row)
        text_matrix.append(text_row)
        customdata.append(cd_row)

    fig = go.Figure(data=go.Heatmap(
        z=z_matrix,
        x=x_labels,
        customdata=customdata,
        hovertext=text_matrix,
        hoverinfo='text',
        colorscale=[
            [0, '#d13b31'],
            [0.2, '#e57339'],
            [0.4, '#e5a839'],
            [0.6, '#e5d439'],
            [0.8, '#7bc043'],
            [1.0, '#2d8a4e'],
        ],
        zmin=0,
        zmax=5,
        colorbar=dict(
            title='Score',
            tickvals=[0, 1, 2, 3, 4, 5],
            ticktext=['0', '1', '2', '3', '4', '5'],
            len=0.5,
        ),
        xgap=2,
        ygap=1,
    ))

    fig.update_layout(
        title=dict(text='ATT&CK Visibility Coverage', font=dict(color='#888', size=14)),
        xaxis=dict(
            side='top', tickangle=-45,
            tickfont=dict(size=10, color='#888'),
        ),
        yaxis=dict(
            autorange='reversed', showticklabels=False,
            title=dict(text='Techniques (sorted by score)', font=dict(size=10, color='#555')),
        ),
        plot_bgcolor='#0f0f23',
        paper_bgcolor='#1a1a2e',
        font=dict(color='#e0e0e0'),
        height=min(max_rows * 8 + 200, 900),
        margin=dict(l=30, r=30, t=100, b=20),
    )

    return html.Div([
        html.Div('VISIBILITY HEATMAP', style={
            'fontSize': '10px', 'letterSpacing': '3px', 'color': '#555',
            'marginBottom': '8px', 'fontFamily': "'Share Tech Mono', monospace",
        }),
        dcc.Graph(
            id='coverage-heatmap',
            figure=fig,
            config={'displayModeBar': True, 'displaylogo': False, 'scrollZoom': True},
        ),
    ])


def _build_data_sources_table(visibility):
    """Table of detected data sources with quality score editing."""
    tech_scores = visibility.get('technique_scores', {})

    # aggregate data components across all techniques
    component_stats = {}
    for tid, info in tech_scores.items():
        for comp in info.get('covered', []):
            if comp not in component_stats:
                component_stats[comp] = {'covered_techniques': 0}
            component_stats[comp]['covered_techniques'] += 1

    table_data = []
    for comp_name, stats in sorted(component_stats.items()):
        table_data.append({
            'component': comp_name,
            'techniques_covered': stats['covered_techniques'],
        })

    return html.Div([
        html.Div('DETECTED DATA COMPONENTS', style={
            'fontSize': '10px', 'letterSpacing': '3px', 'color': '#555',
            'marginBottom': '8px', 'fontFamily': "'Share Tech Mono', monospace",
        }),
        html.Div([
            html.Div('Data components found in the dataset that enable technique detection.',
                     style={'color': '#555', 'fontSize': '11px', 'marginBottom': '10px'}),
            dash_table.DataTable(
                id='data-sources-table',
                columns=[
                    {'name': 'Data Component', 'id': 'component'},
                    {'name': 'Techniques Covered', 'id': 'techniques_covered'},
                ],
                data=table_data,
                page_size=15,
                sort_action='native',
                style_table={'overflowX': 'auto', 'borderRadius': '4px'},
                style_header={
                    'backgroundColor': '#1a1a2e', 'color': '#3498db',
                    'fontWeight': '600', 'fontSize': '11px',
                    'border': '1px solid #2a2a4a',
                    'fontFamily': "'Rajdhani', sans-serif",
                    'letterSpacing': '0.5px', 'textTransform': 'uppercase',
                },
                style_cell={
                    'backgroundColor': '#0f0f23', 'color': '#c0c0c0',
                    'fontSize': '11px', 'border': '1px solid rgba(42, 42, 74, 0.5)',
                    'padding': '6px 10px',
                    'fontFamily': "'Share Tech Mono', monospace",
                },
                style_data_conditional=[{
                    'if': {'state': 'active'},
                    'backgroundColor': 'rgba(52, 152, 219, 0.1)',
                    'border': '1px solid #3498db',
                }],
            ),
        ], style={
            'backgroundColor': 'rgba(15, 15, 35, 0.6)',
            'border': '1px solid #1a1a2e', 'borderRadius': '4px',
            'padding': '12px 15px',
        }),
    ])


def _build_gap_analysis(visibility):
    """Show techniques with zero visibility (gaps)."""
    tech_scores = visibility.get('technique_scores', {})
    gaps = [(tid, info) for tid, info in tech_scores.items()
            if info['score'] == 0 and info.get('required_count', 0) > 0]
    gaps.sort(key=lambda x: x[0])

    if not gaps:
        return html.Div([
            html.Div('GAP ANALYSIS', style={
                'fontSize': '10px', 'letterSpacing': '3px', 'color': '#555',
                'marginBottom': '8px', 'fontFamily': "'Share Tech Mono', monospace",
            }),
            html.P('No coverage gaps detected.', style={'color': '#2ecc71', 'fontSize': '13px'}),
        ])

    gap_rows = []
    for tid, info in gaps[:50]:
        missing = ', '.join(info.get('missing', [])[:3])
        if len(info.get('missing', [])) > 3:
            missing += f' (+{len(info["missing"]) - 3} more)'
        gap_rows.append({
            'technique': tid,
            'name': info.get('name', ''),
            'required': info.get('required_count', 0),
            'missing_components': missing,
        })

    return html.Div([
        html.Div([
            html.Span('GAP ANALYSIS', style={
                'fontSize': '10px', 'letterSpacing': '3px', 'color': '#555',
                'fontFamily': "'Share Tech Mono', monospace",
            }),
            html.Span(f'  ({len(gaps)} techniques with zero visibility)', style={
                'fontSize': '10px', 'color': '#e74c3c',
                'fontFamily': "'Share Tech Mono', monospace",
            }),
        ], style={'marginBottom': '8px'}),
        html.Div([
            dash_table.DataTable(
                id='gap-table',
                columns=[
                    {'name': 'Technique', 'id': 'technique'},
                    {'name': 'Name', 'id': 'name'},
                    {'name': 'Required Components', 'id': 'required'},
                    {'name': 'Missing Data Components', 'id': 'missing_components'},
                ],
                data=gap_rows,
                page_size=15,
                sort_action='native',
                style_table={'overflowX': 'auto', 'borderRadius': '4px'},
                style_header={
                    'backgroundColor': '#1a1a2e', 'color': '#e74c3c',
                    'fontWeight': '600', 'fontSize': '11px',
                    'border': '1px solid #2a2a4a',
                    'fontFamily': "'Rajdhani', sans-serif",
                    'letterSpacing': '0.5px', 'textTransform': 'uppercase',
                },
                style_cell={
                    'backgroundColor': '#0f0f23', 'color': '#c0c0c0',
                    'fontSize': '11px', 'border': '1px solid rgba(42, 42, 74, 0.5)',
                    'padding': '6px 10px', 'maxWidth': '300px',
                    'overflow': 'hidden', 'textOverflow': 'ellipsis',
                    'fontFamily': "'Share Tech Mono', monospace",
                },
            ),
        ], style={
            'backgroundColor': 'rgba(15, 15, 35, 0.6)',
            'border': '1px solid #1a1a2e', 'borderRadius': '4px',
            'padding': '12px 15px',
        }),
        html.Br(),
        # Export button
        html.Div([
            dbc.Button(
                'Export ATT&CK Navigator Layer',
                id='export-navigator-btn',
                color='primary',
                size='sm',
                outline=True,
                style={'letterSpacing': '1px', 'fontSize': '11px'},
            ),
            dcc.Download(id='download-navigator'),
        ], style={'marginTop': '10px'}),
    ])


def _score_color(score):
    """Map a 0-5 score to a color."""
    if isinstance(score, (int, float)):
        score = round(score)
    colors = {
        0: '#d13b31',
        1: '#e57339',
        2: '#e5a839',
        3: '#e5d439',
        4: '#7bc043',
        5: '#2d8a4e',
    }
    return colors.get(score, '#d13b31')
