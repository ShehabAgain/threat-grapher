SIDEBAR_STYLE = {
    'width': '320px',
    'position': 'fixed',
    'top': '56px',
    'left': 0,
    'bottom': 0,
    'padding': '0.75rem',
    'backgroundColor': '#1a1a2e',
    'color': '#e0e0e0',
    'overflowY': 'auto',
    'borderRight': '1px solid #2a2a4a',
    'zIndex': 1000,
}

CONTENT_STYLE = {
    'marginLeft': '340px',
    'padding': '1rem',
    'backgroundColor': '#0f0f23',
    'minHeight': '100vh',
}

NAVBAR_STYLE = {
    'backgroundColor': '#16213e',
    'borderBottom': '1px solid #2a2a4a',
}

CARD_STYLE = {
    'backgroundColor': '#1a1a2e',
    'border': '1px solid #2a2a4a',
    'color': '#e0e0e0',
}

GRAPH_CONFIG = {
    'displayModeBar': True,
    'scrollZoom': True,
    'modeBarButtonsToRemove': ['lasso2d', 'select2d'],
    'displaylogo': False,
}

TECHNIQUE_ITEM_STYLE = {
    'cursor': 'pointer',
    'padding': '6px 10px',
    'marginBottom': '2px',
    'borderRadius': '4px',
    'fontSize': '13px',
    'color': '#c0c0c0',
    'transition': 'background-color 0.2s',
}

TECHNIQUE_ITEM_HOVER_STYLE = {
    **TECHNIQUE_ITEM_STYLE,
    'backgroundColor': '#2a2a4a',
    'color': '#ffffff',
}

BADGE_STYLE = {
    'fontSize': '10px',
    'marginLeft': '5px',
}
