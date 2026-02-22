import re


def detect_format(file_path, sourcetype=None):
    """Detect the log format of a file.

    Returns one of: 'xml_sysmon', 'keyvalue', 'json', 'exchange', 'unknown'
    """
    if sourcetype:
        st = sourcetype.lower()
        if 'xmlwineventlog' in st or 'sysmon' in st:
            return 'xml_sysmon'
        if 'json' in st or 'cloudtrail' in st:
            return 'json'

    if file_path.lower().endswith('.json'):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                head = f.read(500).lstrip()
            if head.startswith('{') or head.startswith('['):
                return 'json'
            # Some .json files are actually IIS/Exchange logs
            if re.match(r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}', head):
                return 'exchange'
        except Exception:
            return 'json'

    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            head = f.read(1000).lstrip()
    except Exception:
        return 'unknown'

    if head.startswith('<Event'):
        return 'xml_sysmon'

    if head.startswith('{'):
        return 'json'

    if head.startswith('['):
        return 'json'

    if 'LogName=' in head and 'EventCode=' in head:
        return 'keyvalue'

    if re.match(r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}', head):
        return 'exchange'

    # Fallback: if it has key=value pairs, use keyvalue
    if '=' in head and '\n' in head:
        lines_with_eq = sum(1 for line in head.split('\n') if '=' in line)
        if lines_with_eq >= 3:
            return 'keyvalue'

    return 'unknown'
