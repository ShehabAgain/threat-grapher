import os
import re
import random
from collections import Counter
from pathlib import Path


def compute_dataset_stats(technique_tree):
    """Compute aggregate statistics across the entire dataset.

    Performs a fast scan of file metadata and samples a subset of files
    to extract EventID distributions without parsing everything.
    """
    techniques = technique_tree.get('techniques', {})
    grouped = technique_tree.get('grouped', {})

    total_files = 0
    total_size = 0
    file_types = Counter()
    all_file_paths = []

    for tid, tdata in techniques.items():
        for f in tdata.get('files', []):
            total_files += 1
            total_size += f.get('size', 0)
            ext = os.path.splitext(f['name'])[1].lower()
            file_types[ext] += 1
            all_file_paths.append(f['path'])

        for sname, sdata in tdata.get('scenarios', {}).items():
            for f in sdata.get('files', []):
                total_files += 1
                total_size += f.get('size', 0)
                ext = os.path.splitext(f['name'])[1].lower()
                file_types[ext] += 1
                all_file_paths.append(f['path'])

    # Sample up to 80 .log files for EventID extraction
    log_files = [p for p in all_file_paths if p.endswith('.log')]
    sample_size = min(80, len(log_files))
    sampled = random.sample(log_files, sample_size) if log_files else []

    event_id_counter = Counter()
    log_sources = Counter()
    sample_event_count = 0

    xml_event_id_re = re.compile(r'<EventID[^>]*>(\d+)</EventID>')
    kv_event_code_re = re.compile(r'^EventCode=(\d+)', re.MULTILINE)
    kv_logname_re = re.compile(r'^LogName=(.+)', re.MULTILINE)
    xml_provider_re = re.compile(r'Provider Name="([^"]+)"')

    for fpath in sampled:
        try:
            size = os.path.getsize(fpath)
            read_limit = min(size, 512 * 1024)  # read up to 512KB per file
            with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                chunk = fh.read(read_limit)

            # Try XML EventIDs
            xml_ids = xml_event_id_re.findall(chunk)
            if xml_ids:
                event_id_counter.update(xml_ids)
                sample_event_count += len(xml_ids)
                providers = xml_provider_re.findall(chunk)
                log_sources.update(providers)
                continue

            # Try key-value EventCodes
            kv_ids = kv_event_code_re.findall(chunk)
            if kv_ids:
                event_id_counter.update(kv_ids)
                sample_event_count += len(kv_ids)
                lognames = kv_logname_re.findall(chunk)
                log_sources.update(ln.strip() for ln in lognames)
        except Exception:
            continue

    # Count unique MITRE techniques referenced in YAML
    mitre_ids = set()
    authors = Counter()
    for tid, tdata in techniques.items():
        yml = tdata.get('yml_data', {})
        if yml:
            for mt in yml.get('mitre_technique', []):
                mitre_ids.add(str(mt))
            author = yml.get('author', '')
            if author:
                authors[author] += 1
        for sname, sdata in tdata.get('scenarios', {}).items():
            syml = sdata.get('yml_data', {})
            if syml:
                for mt in syml.get('mitre_technique', []):
                    mitre_ids.add(str(mt))
                author = syml.get('author', '')
                if author:
                    authors[author] += 1

    return {
        'technique_count': len(techniques),
        'parent_technique_count': len(grouped),
        'total_files': total_files,
        'total_size_bytes': total_size,
        'file_types': dict(file_types.most_common(10)),
        'top_event_ids': dict(event_id_counter.most_common(10)),
        'top_log_sources': dict(log_sources.most_common(8)),
        'sample_event_count': sample_event_count,
        'sampled_files': sample_size,
        'mitre_technique_count': len(mitre_ids),
        'top_authors': dict(authors.most_common(5)),
    }
