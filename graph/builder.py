import math
import networkx as nx
import plotly.graph_objects as go
from graph.entities import extract_entities_and_edges, ENTITY_TYPES


def build_graph(events, format_type, allowed_eids=None):
    """Build a NetworkX directed graph from parsed events."""
    G = nx.DiGraph()

    for event in events:
        if allowed_eids and event.get('EventID', '') not in allowed_eids:
            continue
        nodes, edges = extract_entities_and_edges(event, format_type)

        for node_id, node_attrs in nodes:
            if G.has_node(node_id):
                G.nodes[node_id]['count'] = G.nodes[node_id].get('count', 1) + 1
            else:
                G.add_node(node_id, **node_attrs, count=1)

        for edge_tuple in edges:
            if edge_tuple is None:
                continue
            src, dst, edge_attrs = edge_tuple
            if G.has_edge(src, dst):
                G[src][dst]['weight'] = G[src][dst].get('weight', 1) + 1
            else:
                G.add_edge(src, dst, **edge_attrs, weight=1)

    return G


def graph_to_figure(G, title=''):
    """Convert a NetworkX directed graph to a Plotly figure with arrows."""
    if len(G.nodes()) == 0:
        return None, 600

    num_nodes = len(G.nodes())
    k_value = max(3.5, 1.5 * num_nodes ** 0.45)
    pos = nx.spring_layout(G, k=k_value, iterations=100, seed=42)

    # Dynamic height: sqrt-scaled, caps at 2000px
    fig_height = max(600, min(2000, 500 + int(80 * num_nodes ** 0.5)))

    traces = []

    # Build node type index for legend grouping
    node_types = {}
    for node_id, data in G.nodes(data=True):
        node_types[node_id] = data.get('entity_type', 'unknown')

    # Group edges by destination entity type so they toggle with the legend
    edge_groups = {}   # etype -> {x, y, labels}
    arrow_groups = {}  # etype -> {x, y, angles}

    for u, v, data in G.edges(data=True):
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        weight = data.get('weight', 1)
        label = data.get('label', '')
        label_text = f'{label} (x{weight})' if weight > 1 else label

        dst_type = node_types.get(v, 'unknown')

        # Edge line data
        if dst_type not in edge_groups:
            edge_groups[dst_type] = {'x': [], 'y': [], 'labels': []}
        edge_groups[dst_type]['x'] += [x0, x1, None]
        edge_groups[dst_type]['y'] += [y0, y1, None]
        edge_groups[dst_type]['labels'].append(label_text)

        # Arrow data: place arrowhead at 78% along the edge
        if dst_type not in arrow_groups:
            arrow_groups[dst_type] = {'x': [], 'y': [], 'angles': []}
        frac = 0.78
        ax = x0 + frac * (x1 - x0)
        ay = y0 + frac * (y1 - y0)
        angle_deg = 90 - math.degrees(math.atan2(y1 - y0, x1 - x0))
        arrow_groups[dst_type]['x'].append(ax)
        arrow_groups[dst_type]['y'].append(ay)
        arrow_groups[dst_type]['angles'].append(angle_deg)

    # Edge line traces with hover-only labels
    for etype, edata in edge_groups.items():
        if edata['x']:
            # Build per-point hover text for edge lines
            hover_texts = []
            label_idx = 0
            for i in range(0, len(edata['x']), 3):
                lbl = edata['labels'][label_idx] if label_idx < len(edata['labels']) else ''
                hover_texts.extend([lbl, lbl, ''])
                label_idx += 1

            traces.append(go.Scatter(
                x=edata['x'], y=edata['y'],
                mode='lines',
                line=dict(width=1.0, color='rgba(52, 152, 219, 0.30)'),
                hovertext=hover_texts,
                hoverinfo='text',
                showlegend=False,
                legendgroup=etype,
            ))

    # Arrow marker traces
    use_gl = num_nodes > 200
    scatter_cls = go.Scattergl if use_gl else go.Scatter

    for etype, adata in arrow_groups.items():
        if adata['x']:
            traces.append(scatter_cls(
                x=adata['x'], y=adata['y'],
                mode='markers',
                marker=dict(
                    symbol='triangle-up',
                    size=7,
                    color='rgba(52, 152, 219, 0.65)',
                    angle=adata['angles'],
                    line=dict(width=0),
                ),
                hoverinfo='none',
                showlegend=False,
                legendgroup=etype,
            ))

    # Node traces (one per entity type for legend)
    nodes_by_type = {}
    for node_id, data in G.nodes(data=True):
        etype = data.get('entity_type', 'unknown')
        if etype not in nodes_by_type:
            nodes_by_type[etype] = {'x': [], 'y': [], 'text': [], 'hover': [], 'sizes': []}
        x, y = pos[node_id]
        nodes_by_type[etype]['x'].append(x)
        nodes_by_type[etype]['y'].append(y)
        nodes_by_type[etype]['text'].append(data.get('label', ''))
        count = data.get('count', 1)
        hover = (f"<b>{data.get('label', '')}</b><br>"
                 f"Type: {etype}<br>"
                 f"Full: {data.get('full_value', '')}<br>"
                 f"Occurrences: {count}")
        nodes_by_type[etype]['hover'].append(hover)
        base_size = ENTITY_TYPES.get(etype, {}).get('size', 14)
        scaled = min(base_size + count * 0.5, base_size * 2.5)
        nodes_by_type[etype]['sizes'].append(scaled)

    # Hide text labels for large graphs to reduce clutter
    node_mode = 'markers+text' if num_nodes <= 100 else 'markers'

    for etype, ndata in nodes_by_type.items():
        style = ENTITY_TYPES.get(etype, {'color': '#cccccc', 'symbol': 'circle', 'size': 14})

        node_trace = scatter_cls(
            x=ndata['x'], y=ndata['y'],
            mode=node_mode,
            marker=dict(
                size=ndata['sizes'],
                color=style['color'],
                symbol=style['symbol'],
                line=dict(width=1.5, color='rgba(255, 255, 255, 0.3)'),
                opacity=0.9,
            ),
            text=ndata['text'],
            textposition='top center',
            textfont=dict(size=9, color='rgba(224, 224, 224, 0.7)', family='Share Tech Mono, monospace'),
            hovertext=ndata['hover'],
            hoverinfo='text',
            name=etype.upper(),
            legendgroup=etype,
        )
        traces.append(node_trace)

    fig = go.Figure(data=traces)

    fig.update_layout(
        title=dict(
            text=title or 'Entity Relationship Graph',
            font=dict(size=14, color='#7f8c8d', family='Rajdhani, sans-serif'),
        ),
        font=dict(family='Rajdhani, sans-serif'),
        template='plotly_dark',
        paper_bgcolor='#0f0f23',
        plot_bgcolor='#0f0f23',
        showlegend=True,
        legend=dict(
            bgcolor='rgba(15, 15, 35, 0.9)',
            bordercolor='rgba(42, 42, 74, 0.5)',
            borderwidth=1,
            font=dict(color='#888', size=11, family='Share Tech Mono, monospace'),
            itemsizing='constant',
        ),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        margin=dict(l=20, r=20, t=50, b=20),
        height=fig_height,
        dragmode='pan',
        hovermode='closest',
        hoverlabel=dict(
            bgcolor='#1a1a2e',
            bordercolor='#3498db',
            font=dict(color='#e0e0e0', size=11, family='Share Tech Mono, monospace'),
        ),
        transition=dict(
            duration=500,
            easing='cubic-in-out',
        ),
        uirevision='constant',
    )

    # Add zoom/pan buttons to the graph itself
    fig.update_layout(
        updatemenus=[
            dict(
                type='buttons',
                direction='right',
                x=0.0, y=1.12,
                xanchor='left', yanchor='top',
                bgcolor='rgba(26, 26, 46, 0.8)',
                bordercolor='rgba(42, 42, 74, 0.5)',
                font=dict(color='#e0e0e0', size=10, family='Share Tech Mono, monospace'),
                buttons=[
                    dict(label='  +  ',
                         method='relayout',
                         args=[{'xaxis.range': _zoom_range(pos, 0.6, 'x'),
                                'yaxis.range': _zoom_range(pos, 0.6, 'y')}]),
                    dict(label='  -  ',
                         method='relayout',
                         args=[{'xaxis.range': _zoom_range(pos, 1.6, 'x'),
                                'yaxis.range': _zoom_range(pos, 1.6, 'y')}]),
                    dict(label=' Reset ',
                         method='relayout',
                         args=[{'xaxis.autorange': True,
                                'yaxis.autorange': True}]),
                ],
            ),
        ],
    )

    return fig, fig_height


def _zoom_range(pos, scale, axis):
    """Compute a zoomed axis range centered on the graph."""
    idx = 0 if axis == 'x' else 1
    vals = [coord[idx] for coord in pos.values()]
    center = (min(vals) + max(vals)) / 2
    span = (max(vals) - min(vals)) / 2
    margin = max(span * scale, 0.1)
    return [center - margin, center + margin]
