from dash import html, dcc
import dash_bootstrap_components as dbc
from ui.styles import SIDEBAR_STYLE, CONTENT_STYLE, NAVBAR_STYLE, CARD_STYLE

GOOGLE_FONT_URL = 'https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;500;600;700&family=Share+Tech+Mono&display=swap'


def create_layout(technique_tree, dataset_stats=None, stix_data=None, visibility=None):
    """Create the main Dash layout."""

    # Build coverage tab content if data is available
    coverage_content = html.Div()
    if stix_data and visibility:
        from ui.coverage_layout import build_coverage_tab
        coverage_content = build_coverage_tab(stix_data, visibility)

    return html.Div([

        # Navbar
        dbc.Navbar(
            dbc.Container([
                html.Div([
                    html.Span(
                        'THREAT',
                        style={
                            'fontWeight': '700', 'fontSize': '22px', 'color': '#3498db',
                            'letterSpacing': '2px', 'fontFamily': "'Rajdhani', sans-serif",
                        },
                    ),
                    html.Span(
                        'GRAPHER',
                        style={
                            'fontWeight': '700', 'fontSize': '22px', 'color': '#e0e0e0',
                            'letterSpacing': '2px', 'fontFamily': "'Rajdhani', sans-serif",
                        },
                    ),
                ], style={'display': 'flex', 'alignItems': 'center'}),
                html.Div([
                    html.Div(style={
                        'width': '8px', 'height': '8px', 'borderRadius': '50%',
                        'backgroundColor': '#2ecc71', 'display': 'inline-block',
                        'marginRight': '8px', 'boxShadow': '0 0 6px #2ecc71',
                    }),
                    html.Span(
                        'MITRE ATT&CK VISUALIZER',
                        style={
                            'color': '#555', 'fontSize': '11px', 'letterSpacing': '3px',
                            'fontFamily': "'Share Tech Mono', monospace",
                        },
                    ),
                ], style={'display': 'flex', 'alignItems': 'center', 'marginLeft': '20px'}),
                # View toggle buttons
                html.Div([
                    dbc.ButtonGroup([
                        dbc.Button('Techniques', id='btn-view-techniques', color='primary',
                                   outline=True, size='sm', active=True,
                                   style={'fontSize': '10px', 'letterSpacing': '1px'}),
                        dbc.Button('Coverage', id='btn-view-coverage', color='primary',
                                   outline=True, size='sm',
                                   style={'fontSize': '10px', 'letterSpacing': '1px'}),
                    ]),
                ], style={'marginLeft': 'auto'}),
            ], fluid=True, style={'display': 'flex', 'alignItems': 'center'}),
            style={
                **NAVBAR_STYLE,
                'boxShadow': '0 2px 10px rgba(0, 0, 0, 0.3)',
                'padding': '8px 0',
            },
            dark=True,
            fixed='top',
        ),

        # Sidebar
        html.Div([
            # Sidebar header
            html.Div(
                'TECHNIQUES',
                style={
                    'fontSize': '10px', 'letterSpacing': '3px', 'color': '#555',
                    'marginBottom': '8px', 'paddingBottom': '6px',
                    'borderBottom': '1px solid #2a2a4a',
                    'fontFamily': "'Share Tech Mono', monospace",
                },
            ),
            # Search box
            dbc.Input(
                id='search-input',
                placeholder='Search techniques...',
                type='text',
                size='sm',
                style={
                    'backgroundColor': '#0a0a1a',
                    'border': '1px solid #2a2a4a',
                    'color': '#e0e0e0',
                    'marginBottom': '12px',
                    'borderRadius': '4px',
                    'fontSize': '13px',
                    'fontFamily': "'Share Tech Mono', monospace",
                },
            ),
            # Technique list container
            html.Div(
                id='sidebar-techniques',
                children=_build_sidebar_items(technique_tree),
            ),
        ], style=SIDEBAR_STYLE, id='sidebar-container'),

        # Main content area - Techniques view
        html.Div([
            # Statistics panel (always visible at top)
            _build_stats_panel(dataset_stats) if dataset_stats else html.Div(),

            # Metadata panel
            html.Div(id='metadata-panel', children=[
                _build_welcome_panel(),
            ]),

            html.Br(),

            # Loading indicator + truncation warning
            html.Div(id='loading-info'),

            # File tabs
            html.Div(id='file-tabs-container', children=[]),

            # Graph area (hidden by default, no empty chart)
            dcc.Loading(
                id='graph-loading',
                type='dot',
                color='#3498db',
                children=html.Div(id='graph-container', children=[]),
            ),

            html.Br(),

            # Event data table
            html.Div(id='table-container', children=[]),

        ], style=CONTENT_STYLE, className='main-content', id='techniques-view'),

        # Coverage view (hidden by default)
        html.Div([
            coverage_content,
        ], style={**CONTENT_STYLE, 'marginLeft': '0px', 'display': 'none'}, id='coverage-view'),

        # Hidden stores
        dcc.Store(id='selected-technique', data=None),
        dcc.Store(id='selected-scenario', data=None),
        dcc.Store(id='selected-file-path', data=None),
        dcc.Store(id='current-view', data='techniques'),
    ])


def _build_sidebar_items(technique_tree, search_filter=''):
    """Build the sidebar technique list."""
    if not technique_tree:
        return [html.P('No techniques found', style={'color': '#555'})]

    techniques = technique_tree.get('techniques', {})
    grouped = technique_tree.get('grouped', {})

    items = []
    search_lower = search_filter.lower() if search_filter else ''

    for parent_id in sorted(grouped.keys(), key=lambda x: x):
        sub_ids = grouped[parent_id]
        parent_data = techniques.get(parent_id, {})

        # Filter check
        if search_lower:
            parent_match = search_lower in parent_id.lower()
            sub_match = any(search_lower in sid.lower() for sid in sub_ids)
            desc = parent_data.get('yml_data', {}).get('description', '').lower()
            desc_match = search_lower in desc
            if not (parent_match or sub_match or desc_match):
                continue

        # Build parent item
        description = parent_data.get('yml_data', {}).get('description', '')
        if description and len(description) > 60:
            description = description[:57] + '...'

        file_count = len(parent_data.get('files', []))
        scenario_count = len(parent_data.get('scenarios', {}))
        total_items = file_count + scenario_count + len(sub_ids)

        parent_children = []

        # Top-level files for this technique
        if parent_data.get('files'):
            parent_children.append(
                html.Div(
                    _make_clickable_item(
                        f'  Files ({file_count})',
                        parent_id, '__toplevel__',
                    ),
                    style={'marginLeft': '10px'},
                )
            )

        # Scenarios
        for scenario_name, scenario_data in sorted(parent_data.get('scenarios', {}).items()):
            sc_file_count = len(scenario_data.get('files', []))
            parent_children.append(
                html.Div(
                    _make_clickable_item(
                        f'  {scenario_name}',
                        parent_id, scenario_name,
                        badge_text=str(sc_file_count) if sc_file_count else None,
                    ),
                    style={'marginLeft': '10px'},
                )
            )

        # Sub-techniques
        for sub_id in sub_ids:
            sub_data = techniques.get(sub_id, {})
            sub_desc = sub_data.get('yml_data', {}).get('description', '')
            sub_file_count = len(sub_data.get('files', []))
            sub_scenario_count = len(sub_data.get('scenarios', {}))

            sub_children = []

            if sub_data.get('files'):
                sub_children.append(
                    html.Div(
                        _make_clickable_item(
                            f'    Files ({sub_file_count})',
                            sub_id, '__toplevel__',
                        ),
                        style={'marginLeft': '20px'},
                    )
                )

            for sc_name, sc_data in sorted(sub_data.get('scenarios', {}).items()):
                sc_fc = len(sc_data.get('files', []))
                sub_children.append(
                    html.Div(
                        _make_clickable_item(
                            f'    {sc_name}',
                            sub_id, sc_name,
                            badge_text=str(sc_fc) if sc_fc else None,
                        ),
                        style={'marginLeft': '20px'},
                    )
                )

            parent_children.append(
                html.Details([
                    html.Summary(
                        html.Span([
                            html.Span(sub_id, style={'fontWeight': 'bold', 'color': '#9b59b6'}),
                            dbc.Badge(
                                str(sub_file_count + sub_scenario_count),
                                color='secondary',
                                pill=True,
                                style={'fontSize': '9px', 'marginLeft': '5px'},
                            ) if (sub_file_count + sub_scenario_count) > 0 else None,
                        ]),
                        style={
                            'cursor': 'pointer', 'padding': '4px 0',
                            'fontSize': '12px', 'color': '#b0b0b0',
                            'marginLeft': '10px',
                        },
                    ),
                    html.Div(sub_children),
                ], style={'marginBottom': '2px'})
            )

        # Parent accordion
        items.append(
            html.Details([
                html.Summary(
                    html.Span([
                        html.Span(parent_id, style={'fontWeight': 'bold', 'color': '#3498db'}),
                        html.Span(
                            f' - {description}' if description else '',
                            style={'fontSize': '11px', 'color': '#888', 'marginLeft': '5px'},
                        ),
                        dbc.Badge(
                            str(total_items),
                            color='info',
                            pill=True,
                            style={'fontSize': '9px', 'marginLeft': '8px'},
                        ) if total_items > 0 else None,
                    ]),
                    style={
                        'cursor': 'pointer',
                        'padding': '6px 0',
                        'fontSize': '13px',
                        'borderBottom': '1px solid #2a2a4a',
                    },
                ),
                html.Div(parent_children, style={'paddingLeft': '5px', 'paddingTop': '4px'}),
            ], style={'marginBottom': '4px'})
        )

    return items


def _make_clickable_item(label_text, technique_id, scenario_name, badge_text=None):
    """Create a clickable sidebar item that triggers callbacks."""
    children = [html.Span(label_text, style={'fontSize': '12px'})]
    if badge_text:
        children.append(
            dbc.Badge(badge_text, color='secondary', pill=True,
                      style={'fontSize': '9px', 'marginLeft': '5px'})
        )

    return html.Div(
        children,
        id={'type': 'sidebar-item', 'technique': technique_id, 'scenario': scenario_name},
        n_clicks=0,
        style={
            'cursor': 'pointer',
            'padding': '4px 8px',
            'borderRadius': '3px',
            'color': '#c0c0c0',
            'fontSize': '12px',
        },
        className='sidebar-item',
    )


def _build_welcome_panel():
    """Build the initial welcome panel shown before any technique is selected."""
    return html.Div([
        html.Div([
            html.Div(
                'THREATGRAPHER',
                style={
                    'fontSize': '28px', 'fontWeight': '700', 'letterSpacing': '4px',
                    'color': '#2a2a4a', 'textAlign': 'center', 'marginBottom': '10px',
                    'fontFamily': "'Rajdhani', sans-serif",
                },
            ),
            html.Div(style={
                'width': '60px', 'height': '2px', 'backgroundColor': '#3498db',
                'margin': '0 auto 20px auto', 'boxShadow': '0 0 8px rgba(52, 152, 219, 0.5)',
            }),
            html.P(
                'Select a technique from the sidebar to begin analysis',
                style={
                    'color': '#444', 'textAlign': 'center', 'fontSize': '14px',
                    'letterSpacing': '1px',
                },
            ),
        ], style={'padding': '60px 20px'}),
    ])


def _build_stats_panel(stats):
    """Build the dataset statistics overview panel."""
    if not stats:
        return html.Div()

    def _stat_box(label, value, color='#3498db'):
        return html.Div([
            html.Div(
                str(value),
                style={
                    'fontSize': '24px', 'fontWeight': '700', 'color': color,
                    'fontFamily': "'Share Tech Mono', monospace",
                    'lineHeight': '1',
                },
            ),
            html.Div(
                label,
                style={
                    'fontSize': '9px', 'letterSpacing': '2px', 'color': '#555',
                    'marginTop': '4px', 'textTransform': 'uppercase',
                    'fontFamily': "'Share Tech Mono', monospace",
                },
            ),
        ], style={
            'textAlign': 'center', 'padding': '12px 8px',
            'flex': '1', 'minWidth': '100px',
        })

    # Format total size
    size_bytes = stats.get('total_size_bytes', 0)
    if size_bytes >= 1024 * 1024 * 1024:
        size_str = f'{size_bytes / (1024**3):.1f} GB'
    elif size_bytes >= 1024 * 1024:
        size_str = f'{size_bytes / (1024**2):.0f} MB'
    else:
        size_str = f'{size_bytes / 1024:.0f} KB'

    # Top row: key counters
    top_row = html.Div([
        _stat_box('TECHNIQUES', stats.get('technique_count', 0), '#3498db'),
        _stat_box('MITRE IDS', stats.get('mitre_technique_count', 0), '#9b59b6'),
        _stat_box('LOG FILES', stats.get('total_files', 0), '#2ecc71'),
        _stat_box('TOTAL SIZE', size_str, '#e74c3c'),
        _stat_box('SAMPLED EVENTS', f"{stats.get('sample_event_count', 0):,}", '#f39c12'),
    ], style={
        'display': 'flex', 'justifyContent': 'space-around',
        'borderBottom': '1px solid #1a1a2e', 'paddingBottom': '10px',
        'marginBottom': '10px',
    })

    # Bottom row: top EventIDs and log sources
    bottom_children = []

    top_eids = stats.get('top_event_ids', {})
    if top_eids:
        eid_items = []
        for eid, count in list(top_eids.items())[:6]:
            eid_items.append(html.Span([
                html.Span(f'EID {eid}', style={
                    'color': '#e0e0e0', 'fontSize': '11px',
                    'fontFamily': "'Share Tech Mono', monospace",
                }),
                html.Span(f' ({count:,})', style={
                    'color': '#555', 'fontSize': '10px',
                    'fontFamily': "'Share Tech Mono', monospace",
                }),
            ], style={'marginRight': '14px'}))

        bottom_children.append(
            html.Div([
                html.Span('TOP EVENT IDS  ', style={
                    'fontSize': '9px', 'letterSpacing': '2px', 'color': '#3498db',
                    'marginRight': '10px', 'fontFamily': "'Share Tech Mono', monospace",
                }),
                *eid_items,
            ], style={'marginBottom': '6px'})
        )

    top_sources = stats.get('top_log_sources', {})
    if top_sources:
        src_items = []
        for src, count in list(top_sources.items())[:5]:
            short = src.split('-')[-1] if '-' in src else src
            if len(short) > 25:
                short = short[:22] + '...'
            src_items.append(
                dbc.Badge(
                    f'{short} ({count})',
                    style={
                        'marginRight': '6px', 'fontSize': '9px',
                        'backgroundColor': 'rgba(52, 152, 219, 0.15)',
                        'color': '#888', 'border': '1px solid #2a2a4a',
                        'fontFamily': "'Share Tech Mono', monospace",
                    },
                )
            )

        bottom_children.append(
            html.Div([
                html.Span('LOG SOURCES  ', style={
                    'fontSize': '9px', 'letterSpacing': '2px', 'color': '#3498db',
                    'marginRight': '10px', 'fontFamily': "'Share Tech Mono', monospace",
                }),
                *src_items,
            ])
        )

    return html.Div([
        html.Div(
            'DATASET OVERVIEW',
            style={
                'fontSize': '10px', 'letterSpacing': '3px', 'color': '#555',
                'marginBottom': '8px', 'fontFamily': "'Share Tech Mono', monospace",
            },
        ),
        html.Div([
            top_row,
            html.Div(bottom_children) if bottom_children else html.Div(),
        ], style={
            'backgroundColor': 'rgba(15, 15, 35, 0.6)',
            'border': '1px solid #1a1a2e',
            'borderRadius': '4px',
            'padding': '12px 15px',
            'marginBottom': '15px',
        }),
    ], className='glow-card')
