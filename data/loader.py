import os
from parsers.detect import detect_format
from parsers.xml_sysmon import parse_xml_events
from parsers.keyvalue import parse_keyvalue_events
from parsers.json_logs import parse_json_events
from parsers.exchange import parse_exchange_events


MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
DEFAULT_MAX_EVENTS = 2000

PARSER_MAP = {
    'xml_sysmon': parse_xml_events,
    'keyvalue': parse_keyvalue_events,
    'json': parse_json_events,
    'exchange': parse_exchange_events,
}


def load_file(file_path, max_events=DEFAULT_MAX_EVENTS, sourcetype=None):
    """Load and parse a log/JSON file, returning events and metadata.

    Returns:
        dict with keys:
            'events': list of parsed event dicts
            'format': detected format string
            'total_estimated': estimated total event count
            'loaded': number of events actually loaded
            'truncated': bool whether file was truncated
            'file_size': file size in bytes
            'error': error message if parsing failed, else None
    """
    result = {
        'events': [],
        'format': 'unknown',
        'total_estimated': 0,
        'loaded': 0,
        'truncated': False,
        'file_size': 0,
        'error': None,
    }

    if not os.path.isfile(file_path):
        result['error'] = f'File not found: {file_path}'
        return result

    file_size = os.path.getsize(file_path)
    result['file_size'] = file_size

    fmt = detect_format(file_path, sourcetype)
    result['format'] = fmt

    parser = PARSER_MAP.get(fmt)
    if not parser:
        result['error'] = f'No parser for format: {fmt}'
        return result

    apply_limit = file_size > MAX_FILE_SIZE
    limit = max_events if apply_limit else 0

    try:
        events = parser(file_path, max_events=limit)
    except Exception as e:
        result['error'] = f'Parse error: {str(e)}'
        return result

    result['events'] = events
    result['loaded'] = len(events)

    if apply_limit and len(events) >= max_events:
        result['truncated'] = True
        if events:
            avg_bytes = file_size / max(len(events), 1)
            result['total_estimated'] = int(file_size / max(avg_bytes, 1))
        else:
            result['total_estimated'] = 0
    else:
        result['total_estimated'] = len(events)

    return result
