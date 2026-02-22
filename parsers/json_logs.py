import json


def parse_json_events(file_path, max_events=0):
    """Parse JSON log files. Handles both JSONL (one object per line) and JSON arrays."""
    events = []

    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read().strip()

    if not content:
        return events

    if content.startswith('['):
        try:
            data = json.loads(content)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        events.append(_flatten_json(item))
                        if max_events and len(events) >= max_events:
                            break
        except json.JSONDecodeError:
            pass
        return events

    for line in content.split('\n'):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                events.append(_flatten_json(obj))
            if max_events and len(events) >= max_events:
                break
        except json.JSONDecodeError:
            continue

    return events


def _flatten_json(obj, prefix='', max_depth=3):
    """Flatten nested JSON to a single-level dict for display and graph extraction."""
    flat = {}
    _flatten_recursive(obj, prefix, flat, 0, max_depth)
    return flat


def _flatten_recursive(obj, prefix, flat, depth, max_depth):
    if depth >= max_depth:
        flat[prefix] = str(obj) if obj is not None else ''
        return

    if isinstance(obj, dict):
        for key, value in obj.items():
            new_key = f'{prefix}.{key}' if prefix else key
            _flatten_recursive(value, new_key, flat, depth + 1, max_depth)
    elif isinstance(obj, list):
        if len(obj) <= 5:
            for i, item in enumerate(obj):
                new_key = f'{prefix}[{i}]'
                _flatten_recursive(item, new_key, flat, depth + 1, max_depth)
        else:
            flat[prefix] = str(obj)
    else:
        flat[prefix] = str(obj) if obj is not None else ''
