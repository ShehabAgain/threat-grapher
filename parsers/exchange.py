import re


IIS_FIELDS = [
    'date', 'time', 'server_ip', 'method', 'uri_stem', 'uri_query',
    'port', 'username', 'client_ip', 'user_agent', 'protocol_status',
    'protocol_substatus', 'win32_status', 'time_taken',
]

DATE_LINE_RE = re.compile(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+')


def parse_exchange_events(file_path, max_events=0):
    """Parse IIS/Exchange space-delimited log files."""
    events = []

    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if not DATE_LINE_RE.match(line):
                continue

            parts = line.split()
            event = {}

            for i, field_name in enumerate(IIS_FIELDS):
                if i < len(parts):
                    val = parts[i]
                    event[field_name] = val if val != '-' else ''

            if event.get('date') and event.get('time'):
                event['Timestamp'] = f"{event['date']} {event['time']}"

            if len(parts) > len(IIS_FIELDS):
                event['extra_fields'] = ' '.join(parts[len(IIS_FIELDS):])

            events.append(event)

            if max_events and len(events) >= max_events:
                break

    return events
