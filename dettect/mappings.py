"""
Static mapping from observed log event signatures to MITRE ATT&CK
data sources and data components.

Each key is a (format_type, event_id) tuple matching the format types
from parsers/detect.py and the EventID/EventCode values extracted by
data/stats.py.
"""

# (format_type, event_id_string) -> (data_source_name, data_component_name)
EVENT_TO_DATA_COMPONENT = {
    # --- Sysmon XML events ---
    ('xml_sysmon', '1'):   ('Process', 'Process Creation'),
    ('xml_sysmon', '2'):   ('File', 'File Modification'),
    ('xml_sysmon', '3'):   ('Network Traffic', 'Network Connection Creation'),
    ('xml_sysmon', '5'):   ('Process', 'Process Termination'),
    ('xml_sysmon', '6'):   ('Driver', 'Driver Load'),
    ('xml_sysmon', '7'):   ('Module', 'Module Load'),
    ('xml_sysmon', '8'):   ('Process', 'OS API Execution'),
    ('xml_sysmon', '9'):   ('File', 'File Access'),
    ('xml_sysmon', '10'):  ('Process', 'Process Access'),
    ('xml_sysmon', '11'):  ('File', 'File Creation'),
    ('xml_sysmon', '12'):  ('Windows Registry', 'Windows Registry Key Creation'),
    ('xml_sysmon', '13'):  ('Windows Registry', 'Windows Registry Key Modification'),
    ('xml_sysmon', '14'):  ('Windows Registry', 'Windows Registry Key Modification'),
    ('xml_sysmon', '15'):  ('File', 'File Creation'),
    ('xml_sysmon', '17'):  ('Named Pipe', 'Named Pipe Creation'),
    ('xml_sysmon', '18'):  ('Named Pipe', 'Named Pipe Connection'),
    ('xml_sysmon', '22'):  ('Network Traffic', 'Network Connection Creation'),
    ('xml_sysmon', '23'):  ('File', 'File Deletion'),
    ('xml_sysmon', '25'):  ('Process', 'Process Modification'),
    ('xml_sysmon', '26'):  ('File', 'File Deletion'),

    # --- Windows Security events (keyvalue format) ---
    ('keyvalue', '4688'):  ('Process', 'Process Creation'),
    ('keyvalue', '592'):   ('Process', 'Process Creation'),
    ('keyvalue', '4689'):  ('Process', 'Process Termination'),
    ('keyvalue', '4624'):  ('Logon Session', 'Logon Session Creation'),
    ('keyvalue', '4625'):  ('Logon Session', 'Logon Session Creation'),
    ('keyvalue', '4634'):  ('Logon Session', 'Logon Session Metadata'),
    ('keyvalue', '4648'):  ('Logon Session', 'Logon Session Creation'),
    ('keyvalue', '4663'):  ('File', 'File Access'),
    ('keyvalue', '4670'):  ('File', 'File Modification'),
    ('keyvalue', '4672'):  ('Logon Session', 'Logon Session Creation'),
    ('keyvalue', '4720'):  ('User Account', 'User Account Creation'),
    ('keyvalue', '4722'):  ('User Account', 'User Account Modification'),
    ('keyvalue', '4724'):  ('User Account', 'User Account Modification'),
    ('keyvalue', '4728'):  ('Group', 'Group Modification'),
    ('keyvalue', '4732'):  ('Group', 'Group Modification'),
    ('keyvalue', '4756'):  ('Group', 'Group Modification'),
    ('keyvalue', '4768'):  ('Active Directory', 'Active Directory Credential Request'),
    ('keyvalue', '4769'):  ('Active Directory', 'Active Directory Credential Request'),
    ('keyvalue', '4776'):  ('Active Directory', 'Active Directory Credential Request'),
    ('keyvalue', '7045'):  ('Service', 'Service Creation'),
    ('keyvalue', '7036'):  ('Service', 'Service Metadata'),
    ('keyvalue', '4104'):  ('Script', 'Script Execution'),
    ('keyvalue', '4103'):  ('Script', 'Script Execution'),

    # --- JSON / CloudTrail events ---
    ('json', 'cloudtrail'):          ('Cloud Service', 'Cloud Service Enumeration'),
    ('json', 'AssumeRole'):          ('Cloud Service', 'Cloud Service Enumeration'),
    ('json', 'ConsoleLogin'):        ('Logon Session', 'Logon Session Creation'),
    ('json', 'CreateUser'):          ('User Account', 'User Account Creation'),
    ('json', 'CreateAccessKey'):     ('User Account', 'User Account Modification'),
    ('json', 'PutBucketPolicy'):     ('Cloud Storage', 'Cloud Storage Modification'),
    ('json', 'RunInstances'):        ('Instance', 'Instance Creation'),
    ('json', 'StopInstances'):       ('Instance', 'Instance Modification'),
    ('json', 'TerminateInstances'):  ('Instance', 'Instance Deletion'),
    ('json', 'AuthorizeSecurityGroupIngress'): ('Firewall', 'Firewall Rule Modification'),
}

# Reverse index: data_component_name -> list of (format_type, event_id)
COMPONENT_TO_EVENTS = {}
for key, val in EVENT_TO_DATA_COMPONENT.items():
    dc_name = val[1]
    COMPONENT_TO_EVENTS.setdefault(dc_name, []).append(key)

# Sourcetype hints: map YAML sourcetype strings to format_type
SOURCETYPE_TO_FORMAT = {
    'XmlWinEventLog': 'xml_sysmon',
    'xmlwineventlog': 'xml_sysmon',
    'WinEventLog': 'keyvalue',
    'wineventlog': 'keyvalue',
    'cloudtrail': 'json',
    'aws:cloudtrail': 'json',
    'google:workspace': 'json',
    'o365:management:activity': 'json',
}
