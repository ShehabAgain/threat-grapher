import re
import xml.etree.ElementTree as ET


NAMESPACE_RE = re.compile(r"\s+xmlns(?::\w+)?='[^']*'")


def parse_xml_events(file_path, max_events=0):
    """Parse XML Sysmon/WinEventLog files where each line is an <Event> element."""
    events = []

    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line or not line.startswith('<Event'):
                continue

            clean = NAMESPACE_RE.sub('', line)

            try:
                root = ET.fromstring(clean)
            except ET.ParseError:
                continue

            event = _extract_event(root)
            if event:
                events.append(event)

            if max_events and len(events) >= max_events:
                break

    return events


def _extract_event(root):
    event = {}

    system = root.find('System')
    if system is not None:
        provider = system.find('Provider')
        if provider is not None:
            event['ProviderName'] = provider.get('Name', '')
            event['ProviderGuid'] = provider.get('Guid', '')

        for tag in ('EventID', 'Level', 'Task', 'Opcode', 'Keywords',
                     'EventRecordID', 'Channel', 'Computer'):
            elem = system.find(tag)
            if elem is not None and elem.text:
                event[tag] = elem.text

        tc = system.find('TimeCreated')
        if tc is not None:
            event['TimeCreated'] = tc.get('SystemTime', '')

        execution = system.find('Execution')
        if execution is not None:
            event['ProcessID'] = execution.get('ProcessID', '')
            event['ThreadID'] = execution.get('ThreadID', '')

        security = system.find('Security')
        if security is not None:
            uid = security.get('UserID') or security.get('UserId', '')
            if uid:
                event['UserID'] = uid

    event_data = root.find('EventData')
    if event_data is not None:
        for data in event_data.findall('Data'):
            name = data.get('Name', '')
            value = data.text or ''
            if name:
                event[name] = value

    if not event:
        return None

    return event
