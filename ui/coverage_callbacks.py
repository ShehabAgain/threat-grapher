"""
Callbacks for the coverage dashboard tab.

Handles Navigator layer export and future quality score editing.
"""

import json
from dash import Input, Output
from dettect.visibility import generate_navigator_layer


def register_coverage_callbacks(app, stix_data, coverage_result, visibility, ds_admin):
    """Register coverage-related callbacks."""

    @app.callback(
        Output('download-navigator', 'data'),
        Input('export-navigator-btn', 'n_clicks'),
        prevent_initial_call=True,
    )
    def export_navigator(n_clicks):
        if not n_clicks:
            return None
        tech_scores = visibility.get('technique_scores', {})
        layer = generate_navigator_layer(tech_scores)
        return dict(
            content=json.dumps(layer, indent=2),
            filename='threatgrapher_visibility_layer.json',
            type='text/json',
        )
