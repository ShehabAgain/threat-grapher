from dash import html, dcc, Input, Output, State, callback_context, ALL, MATCH
import dash_bootstrap_components as dbc
from dash.dash_table import DataTable
import json

from data.loader import load_file
from graph.builder import build_graph, graph_to_figure
from ui.styles import CARD_STYLE


def register_callbacks(app, technique_tree, data_dir, max_events, stix_data=None, visibility=None):
    """Register all Dash callbacks."""
    techniques = technique_tree.get('techniques', {})
    stix_techniques = (stix_data or {}).get('techniques', {})
    stix_tactics = (stix_data or {}).get('tactics', {})
    tech_scores = (visibility or {}).get('technique_scores', {})

    @app.callback(
        Output('sidebar-techniques', 'children'),
        Input('search-input', 'value'),
    )
    def filter_sidebar(search_value):
        from ui.layout import _build_sidebar_items
        return _build_sidebar_items(technique_tree, search_filter=search_value or '')

    @app.callback(
        [Output('metadata-panel', 'children'),
         Output('file-tabs-container', 'children'),
         Output('selected-technique', 'data'),
         Output('selected-scenario', 'data')],
        Input({'type': 'sidebar-item', 'technique': ALL, 'scenario': ALL}, 'n_clicks'),
        prevent_initial_call=True,
    )
    def on_sidebar_click(n_clicks_list):
        ctx = callback_context
        if not ctx.triggered:
            return _no_selection()

        triggered = ctx.triggered[0]
        prop_id = triggered['prop_id']

        # Parse the pattern-matching ID
        try:
            id_str = prop_id.rsplit('.', 1)[0]
            id_dict = json.loads(id_str)
            technique_id = id_dict['technique']
            scenario_name = id_dict['scenario']
        except (json.JSONDecodeError, KeyError, IndexError):
            return _no_selection()

        if triggered['value'] == 0:
            return _no_selection()

        tech_data = techniques.get(technique_id)
        if not tech_data:
            return _no_selection()

        # Get the right files and yml_data
        if scenario_name == '__toplevel__':
            files = tech_data.get('files', [])
            yml_data = tech_data.get('yml_data', {})
        else:
            scenario = tech_data.get('scenarios', {}).get(scenario_name, {})
            files = scenario.get('files', [])
            yml_data = scenario.get('yml_data', {}) or tech_data.get('yml_data', {})

        # Build metadata panel
        metadata = _build_metadata_card(technique_id, scenario_name, yml_data,
                                        stix_techniques, stix_tactics, tech_scores)

        # Build file tabs
        if files:
            tabs = dcc.Tabs(
                id='file-tabs',
                value=files[0]['path'],
                children=[
                    dcc.Tab(
                        label=f['name'],
                        value=f['path'],
                        style={
                            'backgroundColor': '#1a1a2e',
                            'color': '#888',
                            'border': '1px solid #2a2a4a',
                            'padding': '6px 12px',
                            'fontSize': '12px',
                        },
                        selected_style={
                            'backgroundColor': '#2a2a4a',
                            'color': '#e0e0e0',
                            'border': '1px solid #3498db',
                            'borderTop': '2px solid #3498db',
                            'padding': '6px 12px',
                            'fontSize': '12px',
                        },
                    )
                    for f in files
                ],
                style={'marginBottom': '10px'},
            )
        else:
            tabs = html.Div(
                html.P('No parseable files in this location.',
                       style={'color': '#555', 'fontSize': '13px', 'padding': '10px'}),
            )

        return metadata, tabs, technique_id, scenario_name

    @app.callback(
        [Output('graph-container', 'children'),
         Output('loading-info', 'children'),
         Output('table-container', 'children')],
        Input('file-tabs', 'value'),
        [State('selected-technique', 'data'),
         State('selected-scenario', 'data')],
        prevent_initial_call=True,
    )
    def on_file_selected(file_path, technique_id, scenario_name):
        if not file_path:
            return [], None, None

        # Get sourcetype hint from yml
        sourcetype = _get_sourcetype(techniques, technique_id, scenario_name, file_path)

        # Load and parse
        result = load_file(file_path, max_events=max_events, sourcetype=sourcetype)

        # Warning banner
        info_children = []
        if result.get('error'):
            info_children.append(
                dbc.Alert(f"Error: {result['error']}", color='danger', dismissable=True)
            )
        if result.get('truncated'):
            info_children.append(
                dbc.Alert(
                    f"Showing first {result['loaded']} of ~{result['total_estimated']} events "
                    f"(file is {result['file_size'] / 1024 / 1024:.1f} MB). ",
                    color='warning',
                    dismissable=True,
                    style={'fontSize': '12px'},
                )
            )

        info_children.append(
            html.Div([
                html.Span('FORMAT ', style={'color': '#3498db', 'fontSize': '10px', 'letterSpacing': '1px'}),
                html.Span(result['format'], style={'color': '#888', 'fontSize': '11px', 'marginRight': '15px',
                                                    'fontFamily': "'Share Tech Mono', monospace"}),
                html.Span('EVENTS ', style={'color': '#3498db', 'fontSize': '10px', 'letterSpacing': '1px'}),
                html.Span(str(result['loaded']), style={'color': '#888', 'fontSize': '11px', 'marginRight': '15px',
                                                         'fontFamily': "'Share Tech Mono', monospace"}),
                html.Span('SIZE ', style={'color': '#3498db', 'fontSize': '10px', 'letterSpacing': '1px'}),
                html.Span(f"{result['file_size'] / 1024:.0f} KB", style={'color': '#888', 'fontSize': '11px',
                                                                          'fontFamily': "'Share Tech Mono', monospace"}),
            ], style={'marginBottom': '10px', 'paddingBottom': '8px', 'borderBottom': '1px solid #1a1a2e'}),
        )

        events = result.get('events', [])

        # Build graph
        graph_content = []
        if events:
            G = build_graph(events, result['format'])
            import os
            title = f"{technique_id} // {os.path.basename(file_path)}  [{len(G.nodes())} nodes | {len(G.edges())} edges]"
            fig = graph_to_figure(G, title=title)
            if fig is not None:
                graph_content = [
                    dcc.Graph(
                        id='graph-display',
                        figure=fig,
                        config={
                            'displayModeBar': True,
                            'scrollZoom': False,
                            'displaylogo': False,
                        },
                        style={'height': '600px'},
                    ),
                ]
            else:
                graph_content = [
                    html.Div(
                        html.P('No graph entities could be extracted from this file.',
                               style={'color': '#444', 'fontSize': '13px', 'textAlign': 'center',
                                      'padding': '40px', 'letterSpacing': '1px'}),
                    ),
                ]
        else:
            graph_content = [
                html.Div(
                    html.P('No graph entities could be extracted from this file.',
                           style={'color': '#444', 'fontSize': '13px', 'textAlign': 'center',
                                  'padding': '40px', 'letterSpacing': '1px'}),
                ),
            ]

        # Build event table
        if events:
            all_keys = set()
            for ev in events[:200]:
                all_keys.update(ev.keys())
            skip_keys = {'Message', 'MessagePreview', 'CommandLine', 'ParentCommandLine'}
            display_keys = sorted(all_keys - skip_keys)[:15]

            columns = [{'name': k, 'id': k} for k in display_keys]
            table_data = []
            for ev in events[:200]:
                row = {}
                for k in display_keys:
                    val = ev.get(k, '')
                    if isinstance(val, str) and len(val) > 100:
                        val = val[:97] + '...'
                    row[k] = val
                table_data.append(row)

            table = html.Div([
                html.Div(
                    'EVENT LOG',
                    style={
                        'fontSize': '10px', 'letterSpacing': '3px', 'color': '#555',
                        'marginBottom': '8px', 'fontFamily': "'Share Tech Mono', monospace",
                    },
                ),
                DataTable(
                    id='event-table',
                    columns=columns,
                    data=table_data,
                    page_size=20,
                    sort_action='native',
                    filter_action='native',
                    style_table={'overflowX': 'auto', 'borderRadius': '4px'},
                    style_header={
                        'backgroundColor': '#1a1a2e',
                        'color': '#3498db',
                        'fontWeight': '600',
                        'fontSize': '11px',
                        'border': '1px solid #2a2a4a',
                        'fontFamily': "'Rajdhani', sans-serif",
                        'letterSpacing': '0.5px',
                        'textTransform': 'uppercase',
                    },
                    style_cell={
                        'backgroundColor': '#0f0f23',
                        'color': '#c0c0c0',
                        'fontSize': '11px',
                        'border': '1px solid rgba(42, 42, 74, 0.5)',
                        'maxWidth': '200px',
                        'overflow': 'hidden',
                        'textOverflow': 'ellipsis',
                        'padding': '6px 10px',
                        'fontFamily': "'Share Tech Mono', monospace",
                    },
                    style_filter={
                        'backgroundColor': '#1a1a2e',
                        'color': '#e0e0e0',
                        'fontSize': '11px',
                        'fontFamily': "'Share Tech Mono', monospace",
                    },
                    style_data_conditional=[{
                        'if': {'state': 'active'},
                        'backgroundColor': 'rgba(52, 152, 219, 0.1)',
                        'border': '1px solid #3498db',
                    }],
                ),
            ])
        else:
            table = None

        return graph_content, html.Div(info_children), table

    # ---- View toggle callback ----
    @app.callback(
        [Output('techniques-view', 'style'),
         Output('coverage-view', 'style'),
         Output('sidebar-container', 'style'),
         Output('btn-view-techniques', 'active'),
         Output('btn-view-coverage', 'active')],
        [Input('btn-view-techniques', 'n_clicks'),
         Input('btn-view-coverage', 'n_clicks')],
        prevent_initial_call=True,
    )
    def toggle_view(tech_clicks, cov_clicks):
        from ui.styles import SIDEBAR_STYLE, CONTENT_STYLE
        ctx = callback_context
        if not ctx.triggered:
            return (CONTENT_STYLE, {**CONTENT_STYLE, 'marginLeft': '0px', 'display': 'none'},
                    SIDEBAR_STYLE, True, False)

        btn_id = ctx.triggered[0]['prop_id'].split('.')[0]
        if btn_id == 'btn-view-coverage':
            return (
                {**CONTENT_STYLE, 'display': 'none'},
                {**CONTENT_STYLE, 'marginLeft': '0px', 'display': 'block', 'paddingTop': '70px'},
                {**SIDEBAR_STYLE, 'display': 'none'},
                False,
                True,
            )
        else:
            return (
                CONTENT_STYLE,
                {**CONTENT_STYLE, 'marginLeft': '0px', 'display': 'none'},
                SIDEBAR_STYLE,
                True,
                False,
            )


def _no_selection():
    from ui.layout import _build_welcome_panel
    return (
        _build_welcome_panel(),
        html.Div(),
        None,
        None,
    )


def _build_metadata_card(technique_id, scenario_name, yml_data,
                         stix_techniques=None, stix_tactics=None, tech_scores=None):
    stix_techniques = stix_techniques or {}
    stix_tactics = stix_tactics or {}
    tech_scores = tech_scores or {}

    card_style = {
        **CARD_STYLE,
        'borderLeft': '3px solid #3498db',
        'borderRadius': '4px',
    }

    # Get STIX enrichment for this technique
    stix_info = stix_techniques.get(technique_id, {})
    vis_info = tech_scores.get(technique_id, {})

    if not yml_data and not stix_info:
        return dbc.Card(
            dbc.CardBody([
                html.H5([
                    html.Span(technique_id, style={
                        'color': '#3498db', 'fontWeight': '700', 'letterSpacing': '1px',
                    }),
                ]),
                html.P(
                    f'Scenario: {scenario_name}' if scenario_name != '__toplevel__' else 'Top-level files',
                    style={'color': '#888', 'fontSize': '13px'},
                ),
                html.P('No metadata available.', style={'color': '#555', 'fontSize': '12px'}),
            ]),
            style=card_style,
            className='glow-card',
        )

    children = []

    # Title with STIX technique name and visibility score badge
    title_parts = [
        html.Span(technique_id, style={
            'color': '#3498db', 'fontWeight': '700', 'fontSize': '20px',
            'letterSpacing': '1px', 'marginRight': '10px',
        }),
    ]
    if stix_info.get('name'):
        title_parts.append(html.Span(
            stix_info['name'],
            style={'color': '#e0e0e0', 'fontSize': '14px', 'fontWeight': '500', 'marginRight': '10px'},
        ))
    if scenario_name != '__toplevel__':
        title_parts.append(html.Span(
            f'// {scenario_name}',
            style={'color': '#9b59b6', 'fontSize': '14px', 'fontWeight': '500'},
        ))
    # Visibility score badge
    if vis_info:
        score = vis_info.get('score', 0)
        score_colors = {0: '#d13b31', 1: '#e57339', 2: '#e5a839', 3: '#e5d439', 4: '#7bc043', 5: '#2d8a4e'}
        title_parts.append(dbc.Badge(
            f'VIS {score}/5',
            style={
                'marginLeft': '10px', 'fontSize': '10px', 'fontWeight': '600',
                'backgroundColor': score_colors.get(score, '#555'),
            },
        ))
    children.append(html.Div(title_parts, style={'marginBottom': '8px'}))

    # Description (prefer YAML, fall back to STIX)
    desc = ''
    if yml_data:
        desc = yml_data.get('description', '')
    if not desc and stix_info:
        desc = stix_info.get('description', '')
    if desc:
        children.append(html.P(desc, style={
            'color': '#b0b0b0', 'fontSize': '13px', 'lineHeight': '1.5',
            'borderLeft': '2px solid #2a2a4a', 'paddingLeft': '10px', 'marginBottom': '10px',
        }))

    # Details row with labels
    details = []
    if yml_data:
        author = yml_data.get('author', '')
        if author:
            details.append(html.Span([
                html.Span('AUTHOR ', style={'color': '#3498db', 'fontSize': '9px', 'letterSpacing': '1px'}),
                html.Span(author, style={'color': '#c0c0c0', 'fontSize': '12px', 'marginRight': '20px'}),
            ]))
        date = yml_data.get('date', '')
        if date:
            details.append(html.Span([
                html.Span('DATE ', style={'color': '#3498db', 'fontSize': '9px', 'letterSpacing': '1px'}),
                html.Span(str(date), style={'color': '#c0c0c0', 'fontSize': '12px', 'marginRight': '20px',
                                             'fontFamily': "'Share Tech Mono', monospace"}),
            ]))
        env = yml_data.get('environment', '')
        if env:
            details.append(html.Span([
                html.Span('ENV ', style={'color': '#3498db', 'fontSize': '9px', 'letterSpacing': '1px'}),
                html.Span(env, style={'color': '#c0c0c0', 'fontSize': '12px',
                                       'fontFamily': "'Share Tech Mono', monospace"}),
            ]))
    if details:
        children.append(html.Div(details, style={'marginBottom': '8px'}))

    # Tactic badges (from STIX)
    tactics = stix_info.get('tactics', [])
    if tactics:
        tactic_badges = []
        for t in tactics:
            tinfo = stix_tactics.get(t, {})
            label = tinfo.get('name', t.replace('-', ' ').title())
            tactic_badges.append(
                dbc.Badge(label, color='warning', pill=True,
                          style={'marginRight': '6px', 'fontSize': '10px',
                                 'letterSpacing': '0.5px', 'fontWeight': '600'})
            )
        children.append(html.Div([
            html.Span('TACTICS ', style={'color': '#f39c12', 'fontSize': '9px',
                                          'letterSpacing': '1px', 'marginRight': '6px'}),
            *tactic_badges,
        ], style={'marginBottom': '6px'}))

    # MITRE technique badges from YAML
    if yml_data:
        mitre_techs = yml_data.get('mitre_technique', [])
        if mitre_techs:
            badges = []
            for t in mitre_techs:
                badges.append(
                    dbc.Badge(str(t), color='primary', pill=True,
                              style={'marginRight': '6px', 'fontSize': '10px',
                                     'letterSpacing': '0.5px', 'fontWeight': '600'})
                )
            children.append(html.Div(badges, style={'marginTop': '5px', 'marginBottom': '6px'}))

    # Data component coverage (from STIX + visibility)
    if vis_info and vis_info.get('required_count', 0) > 0:
        dc_items = []
        covered_set = set(vis_info.get('covered', []))
        for dc in stix_info.get('data_components', []):
            comp_name = dc.get('component', '')
            is_covered = comp_name in covered_set
            icon_style = {'fontSize': '10px', 'marginRight': '4px'}
            if is_covered:
                icon = html.Span('[+]', style={**icon_style, 'color': '#2ecc71'})
            else:
                icon = html.Span('[-]', style={**icon_style, 'color': '#e74c3c'})
            dc_items.append(html.Div([
                icon,
                html.Span(f'{dc.get("source", "")}: ', style={
                    'color': '#888', 'fontSize': '11px',
                    'fontFamily': "'Share Tech Mono', monospace",
                }),
                html.Span(comp_name, style={
                    'color': '#2ecc71' if is_covered else '#e74c3c',
                    'fontSize': '11px',
                    'fontFamily': "'Share Tech Mono', monospace",
                }),
            ], style={'marginBottom': '2px'}))

        if dc_items:
            children.append(html.Div([
                html.Div([
                    html.Span('DATA COMPONENTS ', style={
                        'color': '#3498db', 'fontSize': '9px', 'letterSpacing': '1px',
                    }),
                    html.Span(
                        f'({vis_info.get("covered_count", 0)}/{vis_info.get("required_count", 0)} covered)',
                        style={'color': '#888', 'fontSize': '10px', 'marginLeft': '6px',
                               'fontFamily': "'Share Tech Mono', monospace"},
                    ),
                ], style={'marginBottom': '4px'}),
                html.Div(dc_items, style={
                    'backgroundColor': '#0a0a1a', 'borderRadius': '4px',
                    'padding': '6px 10px', 'border': '1px solid #2a2a4a',
                }),
            ], style={'marginTop': '8px'}))

    return dbc.Card(dbc.CardBody(children), style=card_style, className='glow-card')


def _get_sourcetype(techniques, technique_id, scenario_name, file_path):
    """Try to extract sourcetype from YAML datasets config."""
    tech_data = techniques.get(technique_id, {})

    yml_data = None
    if scenario_name == '__toplevel__':
        yml_data = tech_data.get('yml_data', {})
    else:
        scenario = tech_data.get('scenarios', {}).get(scenario_name, {})
        yml_data = scenario.get('yml_data', {}) or tech_data.get('yml_data', {})

    if not yml_data:
        return None

    import os
    file_name = os.path.basename(file_path)
    datasets = yml_data.get('datasets', [])
    if isinstance(datasets, list):
        for ds in datasets:
            if isinstance(ds, dict):
                ds_name = ds.get('name', '')
                ds_source = ds.get('sourcetype', '') or ds.get('source', '')
                if ds_name and ds_name in file_name:
                    return ds_source

    return None
