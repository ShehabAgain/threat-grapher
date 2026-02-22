import re


TIMESTAMP_RE = re.compile(
    r'^\d{2}/\d{2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+(?:AM|PM)$'
)


def parse_keyvalue_events(file_path, max_events=0):
    """Parse plain-text key=value Windows event logs.

    Events are separated by timestamp lines (MM/DD/YYYY HH:MM:SS AM/PM).
    """
    events = []
    current_event = {}
    current_key = None
    in_message = False

    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.rstrip('\n\r')

            if TIMESTAMP_RE.match(line.strip()):
                if current_event:
                    _finalize_event(current_event)
                    events.append(current_event)
                    if max_events and len(events) >= max_events:
                        return events
                current_event = {'Timestamp': line.strip()}
                current_key = None
                in_message = False
                continue

            if not current_event:
                continue

            if not in_message and '=' in line and not line.startswith(' ') and not line.startswith('\t'):
                key, _, value = line.partition('=')
                key = key.strip()
                if key and _is_valid_key(key):
                    current_key = key
                    current_event[current_key] = value.strip()
                    if key == 'Message':
                        in_message = True
                    continue

            if in_message and current_key == 'Message':
                current_event['Message'] = current_event.get('Message', '') + '\n' + line
            elif current_key and line.strip():
                current_event[current_key] = current_event.get(current_key, '') + '\n' + line

    if current_event:
        _finalize_event(current_event)
        events.append(current_event)

    return events


def _is_valid_key(key):
    return bool(re.match(r'^[A-Za-z_][A-Za-z0-9_ ]*$', key))


def _finalize_event(event):
    msg = event.get('Message', '')
    if msg:
        event['Message'] = msg.strip()
        if len(msg) > 500:
            event['MessagePreview'] = msg[:500] + '...'
