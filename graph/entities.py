import os
import re


ENTITY_TYPES = {
    'process':  {'color': '#e74c3c', 'symbol': 'diamond',       'size': 18},
    'file':     {'color': '#2ecc71', 'symbol': 'square',        'size': 14},
    'host':     {'color': '#3498db', 'symbol': 'circle',        'size': 22},
    'user':     {'color': '#f39c12', 'symbol': 'star',          'size': 16},
    'ip':       {'color': '#9b59b6', 'symbol': 'triangle-up',   'size': 16},
    'service':  {'color': '#1abc9c', 'symbol': 'pentagon',      'size': 14},
    'registry': {'color': '#e67e22', 'symbol': 'hexagon',       'size': 12},
    'driver':   {'color': '#34495e', 'symbol': 'bowtie',        'size': 14},
    'hash':     {'color': '#95a5a6', 'symbol': 'cross',         'size': 10},
    'api_call': {'color': '#d35400', 'symbol': 'hourglass',     'size': 14},
    'resource': {'color': '#16a085', 'symbol': 'hexagon2',      'size': 14},
    'dns':      {'color': '#8e44ad', 'symbol': 'diamond-tall',  'size': 12},
}


def _node(entity_type, value, label=None):
    if not value or value == '-' or value == 'NOT_TRANSLATED':
        return None
    normalized = value.strip().lower().replace('\\\\', '\\')
    node_id = f'{entity_type}::{normalized}'
    short_label = label or _short_label(value, entity_type)
    return (node_id, {
        'entity_type': entity_type,
        'label': short_label,
        'full_value': value.strip(),
    })


def _short_label(value, entity_type):
    if entity_type in ('process', 'file', 'driver'):
        name = os.path.basename(value.strip().rstrip('\\').rstrip('/'))
        return name if name else value[:40]
    if len(value) > 50:
        return value[:47] + '...'
    return value


def _edge(src_id, dst_id, label, relation='related'):
    if not src_id or not dst_id:
        return None
    return (src_id, dst_id, {'label': label, 'relation': relation})


def extract_entities_and_edges(event, format_type):
    """Extract graph nodes and edges from a parsed event dict."""
    if format_type == 'xml_sysmon':
        return _extract_sysmon(event)
    elif format_type == 'keyvalue':
        return _extract_keyvalue(event)
    elif format_type == 'json':
        return _extract_json(event)
    elif format_type == 'exchange':
        return _extract_exchange(event)
    return [], []


def _extract_sysmon(event):
    nodes = []
    edges = []
    eid = event.get('EventID', '')

    computer = event.get('Computer', '')
    host_node = _node('host', computer)
    if host_node:
        nodes.append(host_node)

    if eid == '1':  # Process Create
        image = event.get('Image', '')
        parent = event.get('ParentImage', '')
        user = event.get('User', '')

        img_node = _node('process', image)
        par_node = _node('process', parent)
        usr_node = _node('user', user)

        for n in (img_node, par_node, usr_node):
            if n:
                nodes.append(n)

        if par_node and img_node:
            edges.append(_edge(par_node[0], img_node[0], 'spawned', 'process_creation'))
        if usr_node and img_node:
            edges.append(_edge(usr_node[0], img_node[0], 'ran', 'execution'))
        if img_node and host_node:
            edges.append(_edge(img_node[0], host_node[0], 'on', 'host_activity'))

    elif eid == '3':  # Network Connection
        image = event.get('Image', '')
        src_ip = event.get('SourceIp', '')
        dst_ip = event.get('DestinationIp', '')
        dst_port = event.get('DestinationPort', '')

        img_node = _node('process', image)
        src_node = _node('ip', src_ip)
        dst_node = _node('ip', dst_ip)

        for n in (img_node, src_node, dst_node):
            if n:
                nodes.append(n)

        if img_node and dst_node:
            label = f'connected:{dst_port}' if dst_port else 'connected'
            edges.append(_edge(img_node[0], dst_node[0], label, 'network'))
        if src_node and img_node:
            edges.append(_edge(src_node[0], img_node[0], 'source', 'network'))

    elif eid == '6':  # Driver Loaded
        driver = event.get('ImageLoaded', '')
        drv_node = _node('driver', driver)
        if drv_node:
            nodes.append(drv_node)
        if host_node and drv_node:
            edges.append(_edge(host_node[0], drv_node[0], 'loaded_driver', 'driver_load'))

    elif eid == '7':  # Image Loaded (DLL)
        image = event.get('Image', '')
        loaded = event.get('ImageLoaded', '')
        img_node = _node('process', image)
        file_node = _node('file', loaded)
        for n in (img_node, file_node):
            if n:
                nodes.append(n)
        if img_node and file_node:
            edges.append(_edge(img_node[0], file_node[0], 'loaded', 'image_load'))

    elif eid in ('8', '10'):  # CreateRemoteThread / ProcessAccess
        source = event.get('SourceImage', '')
        target = event.get('TargetImage', '')
        src_node = _node('process', source)
        tgt_node = _node('process', target)
        for n in (src_node, tgt_node):
            if n:
                nodes.append(n)
        label = 'injected_into' if eid == '8' else 'accessed'
        if src_node and tgt_node:
            edges.append(_edge(src_node[0], tgt_node[0], label, 'process_interaction'))

    elif eid == '11':  # File Create
        image = event.get('Image', '')
        target = event.get('TargetFilename', '')
        img_node = _node('process', image)
        file_node = _node('file', target)
        for n in (img_node, file_node):
            if n:
                nodes.append(n)
        if img_node and file_node:
            edges.append(_edge(img_node[0], file_node[0], 'created_file', 'file_creation'))

    elif eid in ('12', '13', '14'):  # Registry
        image = event.get('Image', '')
        target = event.get('TargetObject', '')
        img_node = _node('process', image)
        reg_node = _node('registry', target)
        for n in (img_node, reg_node):
            if n:
                nodes.append(n)
        if img_node and reg_node:
            edges.append(_edge(img_node[0], reg_node[0], 'modified_registry', 'registry'))

    elif eid == '22':  # DNS Query
        image = event.get('Image', '')
        query = event.get('QueryName', '')
        img_node = _node('process', image)
        dns_node = _node('dns', query)
        for n in (img_node, dns_node):
            if n:
                nodes.append(n)
        if img_node and dns_node:
            edges.append(_edge(img_node[0], dns_node[0], 'dns_query', 'dns'))

    else:
        # Generic sysmon: extract what we can
        image = event.get('Image', '')
        user = event.get('User', '')
        img_node = _node('process', image) if image else None
        usr_node = _node('user', user) if user else None
        for n in (img_node, usr_node):
            if n:
                nodes.append(n)
        if img_node and host_node:
            edges.append(_edge(img_node[0], host_node[0], f'event_{eid}', 'activity'))
        if usr_node and img_node:
            edges.append(_edge(usr_node[0], img_node[0], 'associated', 'user_activity'))

    return nodes, edges


def _extract_keyvalue(event):
    nodes = []
    edges = []

    computer = event.get('ComputerName', '')
    user = event.get('User', '')
    event_code = event.get('EventCode', '')

    host_node = _node('host', computer)
    usr_node = _node('user', user)

    for n in (host_node, usr_node):
        if n:
            nodes.append(n)

    if event_code == '7045':  # Service Install
        msg = event.get('Message', '')
        svc_name = _extract_field(msg, 'Service Name')
        svc_file = _extract_field(msg, 'Service File Name')

        svc_node = _node('service', svc_name) if svc_name else None
        file_node = _node('file', svc_file) if svc_file else None

        for n in (svc_node, file_node):
            if n:
                nodes.append(n)
        if host_node and svc_node:
            edges.append(_edge(host_node[0], svc_node[0], 'installed_service', 'service_install'))
        if svc_node and file_node:
            edges.append(_edge(svc_node[0], file_node[0], 'image_path', 'service_binary'))

    elif event_code in ('4688', '592'):  # Process Create
        msg = event.get('Message', '')
        new_proc = _extract_field(msg, 'New Process Name') or _extract_field(msg, 'Process Name')
        parent = _extract_field(msg, 'Creator Process Name') or _extract_field(msg, 'Parent Process Name')

        proc_node = _node('process', new_proc) if new_proc else None
        par_node = _node('process', parent) if parent else None

        for n in (proc_node, par_node):
            if n:
                nodes.append(n)
        if par_node and proc_node:
            edges.append(_edge(par_node[0], proc_node[0], 'spawned', 'process_creation'))
        if usr_node and proc_node:
            edges.append(_edge(usr_node[0], proc_node[0], 'ran', 'execution'))

    elif event_code in ('4624', '4625'):  # Logon Success/Failure
        msg = event.get('Message', '')
        ip = _extract_field(msg, 'Source Network Address')

        ip_node = _node('ip', ip) if ip else None
        if ip_node:
            nodes.append(ip_node)

        label = 'logged_on' if event_code == '4624' else 'failed_logon'
        if usr_node and host_node:
            edges.append(_edge(usr_node[0], host_node[0], label, 'authentication'))
        if ip_node and host_node:
            edges.append(_edge(ip_node[0], host_node[0], 'logon_source', 'network'))

    elif event_code == '4104':  # PowerShell Script Block
        if usr_node and host_node:
            edges.append(_edge(usr_node[0], host_node[0], 'executed_script', 'script_execution'))

    else:
        # Generic: connect user to host
        if usr_node and host_node:
            edges.append(_edge(usr_node[0], host_node[0], f'event_{event_code}', 'activity'))

    return nodes, edges


def _extract_field(message, field_name):
    if not message:
        return None
    pattern = re.compile(rf'{re.escape(field_name)}\s*[:=]\s*(.+)', re.IGNORECASE)
    match = pattern.search(message)
    if match:
        return match.group(1).strip()
    return None


def _extract_json(event):
    nodes = []
    edges = []

    # CloudTrail pattern
    user_name = (event.get('userIdentity.userName') or
                 event.get('userIdentity.arn', '').split('/')[-1] if event.get('userIdentity.arn') else '' or
                 event.get('userIdentity.principalId', '') or
                 event.get('user.username', '') or
                 event.get('userName', '') or
                 event.get('actor.email', '') or
                 'unknown')

    if user_name and user_name != 'unknown':
        usr_node = _node('user', user_name)
        if usr_node:
            nodes.append(usr_node)
    else:
        usr_node = None

    src_ip = (event.get('sourceIPAddress') or
              event.get('sourceIPs[0]') or
              event.get('source.ip', ''))
    if src_ip:
        ip_node = _node('ip', src_ip)
        if ip_node:
            nodes.append(ip_node)
            if usr_node:
                edges.append(_edge(usr_node[0], ip_node[0], 'from_ip', 'source'))
    else:
        ip_node = None

    event_name = (event.get('eventName') or
                  event.get('verb') or
                  event.get('operation', ''))
    if event_name:
        api_node = _node('api_call', event_name)
        if api_node:
            nodes.append(api_node)
            if usr_node:
                edges.append(_edge(usr_node[0], api_node[0], 'called', 'api_call'))

        # Extract target resource
        target = (event.get('requestParameters.userName') or
                  event.get('requestParameters.bucketName') or
                  event.get('requestParameters.instanceId') or
                  event.get('objectRef.resource') or
                  event.get('requestURI', ''))
        if target:
            res_node = _node('resource', target)
            if res_node:
                nodes.append(res_node)
                edges.append(_edge(api_node[0], res_node[0], 'on_resource', 'target'))

    # AWS account / region as host
    account = event.get('recipientAccountId', '') or event.get('accountId', '')
    region = event.get('awsRegion', '')
    if account:
        host_label = f'{account}/{region}' if region else account
        host_node = _node('host', host_label)
        if host_node:
            nodes.append(host_node)

    return nodes, edges


def _extract_exchange(event):
    nodes = []
    edges = []

    client_ip = event.get('client_ip', '')
    server_ip = event.get('server_ip', '')
    username = event.get('username', '')
    method = event.get('method', '')
    uri = event.get('uri_stem', '')
    status = event.get('protocol_status', '')

    cli_node = _node('ip', client_ip) if client_ip else None
    srv_node = _node('ip', server_ip, label=f'server:{server_ip}') if server_ip else None
    usr_node = _node('user', username) if username else None

    for n in (cli_node, srv_node, usr_node):
        if n:
            nodes.append(n)

    if method and uri:
        resource = f'{method} {uri}'
        res_node = _node('resource', resource)
        if res_node:
            nodes.append(res_node)
            if cli_node:
                label = f'{method} ({status})' if status else method
                edges.append(_edge(cli_node[0], res_node[0], label, 'http_request'))
            if srv_node:
                edges.append(_edge(res_node[0], srv_node[0], 'served_by', 'server'))

    if usr_node and cli_node:
        edges.append(_edge(usr_node[0], cli_node[0], 'from', 'user_source'))

    return nodes, edges
