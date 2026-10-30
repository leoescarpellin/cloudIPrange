import requests
from bs4 import BeautifulSoup
import json
import os
import re
import shutil
import gzip
from datetime import datetime, timezone
import logging
import sys
import ipaddress
from typing import List, Tuple, Iterable, Dict, Any, Set

# Configuration
AZURE_DOWNLOAD_URL = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
AWS_IP_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
GCP_IP_RANGES_URL = "https://www.gstatic.com/ipranges/cloud.json"
CLOUDFLARE_IPS_URL = "https://api.cloudflare.com/client/v4/ips"

RETENTION_WEEKS = 12

DOCS_DIR = "docs"
TEMP_DIR = "docs_temp"

# Azure paths (both legacy root and namespaced)
OUTPUT_SERVICES_DIR = os.path.join(DOCS_DIR, "ranges-services")
OUTPUT_REGIONS_DIR = os.path.join(DOCS_DIR, "ranges-regions")
JSON_DIR = os.path.join(DOCS_DIR, "json-history")

AZURE_DIR = os.path.join(DOCS_DIR, "azure")
AZURE_SERVICES_DIR = os.path.join(AZURE_DIR, "ranges-services")
AZURE_REGIONS_DIR = os.path.join(AZURE_DIR, "ranges-regions")
AZURE_JSON_DIR = os.path.join(AZURE_DIR, "json-history")

# AWS paths
AWS_DIR = os.path.join(DOCS_DIR, "aws")
AWS_SERVICES_DIR = os.path.join(AWS_DIR, "ranges-services")
AWS_REGIONS_DIR = os.path.join(AWS_DIR, "ranges-regions")
AWS_JSON_DIR = os.path.join(AWS_DIR, "json-history")

# GCP paths
GCP_DIR = os.path.join(DOCS_DIR, "gcp")
GCP_REGIONS_DIR = os.path.join(GCP_DIR, "ranges-regions")
GCP_JSON_DIR = os.path.join(GCP_DIR, "json-history")

# Cloudflare paths
CF_DIR = os.path.join(DOCS_DIR, "cloudflare")
CF_JSON_DIR = os.path.join(CF_DIR, "json-history")

TEMPLATE_FILE = "templates/index_template.html"
INDEX_FILE = os.path.join(DOCS_DIR, "index.html")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

def ensure_directories() -> None:
    """Ensure all required output and temporary directories exist."""
    directories = [
        DOCS_DIR,
        TEMP_DIR,
        OUTPUT_SERVICES_DIR,
        OUTPUT_REGIONS_DIR,
        JSON_DIR,
        AZURE_DIR,
        AZURE_SERVICES_DIR,
        AZURE_REGIONS_DIR,
        AZURE_JSON_DIR,
        AWS_DIR,
        AWS_SERVICES_DIR,
        AWS_REGIONS_DIR,
        AWS_JSON_DIR,
        GCP_DIR,
        GCP_REGIONS_DIR,
        GCP_JSON_DIR,
        CF_DIR,
        CF_JSON_DIR
    ]
    for directory in directories:
        os.makedirs(directory, exist_ok=True)

def process_prefixes(prefixes: Iterable[str]) -> Tuple[List[str], List[str]]:
    """
    Deduplicate, collapse overlapping/contained CIDR subnets, and sort into IPv4 and IPv6.
    Uses ipaddress.collapse_addresses to eliminate redundant child subnets (e.g. /26 inside /16)
    and merge contiguous blocks into optimal supernets.
    Sorted by numerical network address, then prefix length.
    """
    v4_nets: List[ipaddress.IPv4Network] = []
    v6_nets: List[ipaddress.IPv6Network] = []

    for p in prefixes:
        p = p.strip()
        if not p:
            continue
        try:
            if ":" in p:
                v6_nets.append(ipaddress.IPv6Network(p, strict=False))
            else:
                v4_nets.append(ipaddress.IPv4Network(p, strict=False))
        except ValueError as err:
            logging.debug(f"Invalid IP prefix skipped: {p} ({err})")

    collapsed_v4 = list(ipaddress.collapse_addresses(v4_nets))
    collapsed_v6 = list(ipaddress.collapse_addresses(v6_nets))

    sorted_v4 = [
        str(net) for net in sorted(
            collapsed_v4,
            key=lambda c: (int(c.network_address), c.prefixlen)
        )
    ]

    sorted_v6 = [
        str(net) for net in sorted(
            collapsed_v6,
            key=lambda c: (int(c.network_address), c.prefixlen)
        )
    ]

    return sorted_v4, sorted_v6

def write_range_files(target_dir: str, name: str, v4_list: List[str], v6_list: List[str]) -> None:
    """
    Writes:
      - <name>.txt       -> combined IPv4 + IPv6 (sorted)
      - <name>.ipv4.txt  -> IPv4 only (if present)
      - <name>.ipv6.txt  -> IPv6 only (if present)
    """
    os.makedirs(target_dir, exist_ok=True)
    combined = v4_list + v6_list
    full_path = os.path.join(target_dir, f"{name}.txt")
    with open(full_path, "w", encoding="utf-8") as f:
        f.write("\n".join(combined) + ("\n" if combined else ""))

    if v4_list:
        v4_path = os.path.join(target_dir, f"{name}.ipv4.txt")
        with open(v4_path, "w", encoding="utf-8") as f:
            f.write("\n".join(v4_list) + "\n")

    if v6_list:
        v6_path = os.path.join(target_dir, f"{name}.ipv6.txt")
        with open(v6_path, "w", encoding="utf-8") as f:
            f.write("\n".join(v6_list) + "\n")

def format_file_size(size_in_bytes: int) -> str:
    """Format file size in human-readable units."""
    if size_in_bytes < 1024:
        return f"{size_in_bytes} B"
    elif size_in_bytes < 1024 * 1024:
        return f"{size_in_bytes / 1024:.1f} KB"
    else:
        return f"{size_in_bytes / (1024 * 1024):.2f} MB"

def generate_directory_index(
    directory: str,
    output_file: str,
    title: str,
    description: str,
    badge_label: str = "Files"
) -> None:
    """Generate a modern, responsive HTML index with search/filter for files in a directory."""
    try:
        files = [
            f for f in sorted(os.listdir(directory))
            if not f.startswith('.') and f != os.path.basename(output_file)
        ]

        rel_home = os.path.relpath(DOCS_DIR, directory)
        home_href = os.path.normpath(os.path.join(rel_home, "index.html")).replace("\\", "/")

        file_items = []
        for file in files:
            file_path = os.path.join(directory, file)
            if not os.path.isfile(file_path):
                continue
            size = os.path.getsize(file_path)
            size_str = format_file_size(size)

            tag_class = "tag-all"
            tag_name = "ALL"
            if file.endswith(".ipv4.txt"):
                tag_class = "tag-ipv4"
                tag_name = "IPv4"
            elif file.endswith(".ipv6.txt"):
                tag_class = "tag-ipv6"
                tag_name = "IPv6"
            elif file.endswith(".json.gz"):
                tag_class = "tag-gz"
                tag_name = "JSON.GZ"
            elif file.endswith(".json"):
                tag_class = "tag-json"
                tag_name = "JSON"

            # Count records (CIDRs for text files, tags for JSON)
            records_count = None
            if file.endswith(".txt"):
                try:
                    with open(file_path, "r", encoding="utf-8") as rf:
                        records_count = sum(1 for line in rf if line.strip())
                except Exception:
                    pass
            elif file.endswith(".json.gz"):
                try:
                    with gzip.open(file_path, "rb") as gf:
                        jdata = json.load(gf)
                        records_count = len(jdata.get("values", [])) or len(jdata.get("prefixes", []))
                except Exception:
                    pass
            elif file.endswith(".json"):
                try:
                    with open(file_path, "r", encoding="utf-8") as jf:
                        jdata = json.load(jf)
                        records_count = len(jdata.get("values", [])) or len(jdata.get("prefixes", [])) or len(jdata.get("result", {}).get("ipv4_cidrs", []))
                except Exception:
                    pass

            if records_count is not None:
                record_icon = "fa-tags" if "json" in file.lower() else "fa-list-ol"
                record_label = "items" if "json" in file.lower() else "CIDRs"
                records_html = (
                    f'<span class="badge-records" title="{records_count:,} {record_label}">'
                    f'<i class="fa-solid {record_icon}"></i> {records_count:,}'
                    f'</span>'
                )
                search_data = f"{file.lower()} {records_count}"
            else:
                records_html = '<span style="color: var(--text-muted);">&mdash;</span>'
                search_data = file.lower()

            file_items.append(
                f'<tr class="file-row" data-name="{search_data}">'
                f'<td><a class="file-name" href="{file}">{file}</a></td>'
                f'<td><span class="badge {tag_class}">{tag_name}</span></td>'
                f'<td>{records_html}</td>'
                f'<td class="file-size">{size_str}</td>'
                f'<td><a class="action-btn" href="{file}" download title="Download file"><i class="fa-solid fa-download"></i></a></td>'
                f'</tr>'
            )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} – Cloud IP Ranges Hub</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
    <style>
        :root {{
            --primary: #0078d4;
            --primary-hover: #005a9e;
            --bg: #f4f6f9;
            --card-bg: #ffffff;
            --text: #24292f;
            --text-muted: #57606a;
            --border: #d0d7de;
            --radius: 8px;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 24px 16px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
            background: var(--card-bg);
            border-radius: var(--radius);
            box-shadow: 0 4px 12px rgba(0,0,0,0.06);
            border: 1px solid var(--border);
            padding: 32px;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
            border-bottom: 2px solid #eef2f5;
            padding-bottom: 20px;
            margin-bottom: 24px;
        }}
        h1 {{
            margin: 0;
            color: var(--primary);
            font-size: 1.75rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .btn-back {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            color: var(--primary);
            text-decoration: none;
            font-weight: 500;
            padding: 8px 14px;
            background: #eef6fc;
            border-radius: 6px;
            transition: all 0.2s ease;
        }}
        .btn-back:hover {{
            background: #dbebfa;
            color: var(--primary-hover);
        }}
        p.desc {{
            color: var(--text-muted);
            margin-top: 0;
            margin-bottom: 20px;
        }}
        .search-container {{
            margin-bottom: 20px;
            position: relative;
        }}
        .search-input {{
            width: 100%;
            padding: 12px 16px 12px 42px;
            font-size: 0.95rem;
            border: 1px solid var(--border);
            border-radius: 6px;
            outline: none;
            transition: border-color 0.2s;
        }}
        .search-input:focus {{
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(0, 120, 212, 0.15);
        }}
        .search-icon {{
            position: absolute;
            left: 14px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-muted);
        }}
        .stats-bar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.88rem;
            color: var(--text-muted);
            margin-bottom: 12px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.92rem;
        }}
        th, td {{
            padding: 12px 14px;
            text-align: left;
            border-bottom: 1px solid #edf2f7;
        }}
        th {{
            background-color: #f8fafc;
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.78rem;
            letter-spacing: 0.5px;
        }}
        tr:hover td {{
            background-color: #fbfcfe;
        }}
        .file-name {{
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
            color: var(--primary);
            text-decoration: none;
            font-weight: 500;
        }}
        .file-name:hover {{
            text-decoration: underline;
        }}
        .file-size {{
            color: var(--text-muted);
            font-size: 0.88rem;
        }}
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            font-size: 0.75rem;
            font-weight: 600;
            border-radius: 12px;
            text-transform: uppercase;
        }}
        .tag-all {{ background: #e3f2fd; color: #0d47a1; }}
        .tag-ipv4 {{ background: #e8f5e9; color: #1b5e20; }}
        .tag-ipv6 {{ background: #fff3e0; color: #e65100; }}
        .tag-json {{ background: #ede7f6; color: #4a148c; }}
        .tag-gz {{ background: #e0f2fe; color: #0369a1; }}
        .badge-records {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 2px 8px;
            background: #f1f5f9;
            color: #334155;
            border-radius: 12px;
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
            font-size: 0.8rem;
            font-weight: 600;
            border: 1px solid #e2e8f0;
        }}
        .badge-records i {{
            color: var(--primary);
            font-size: 0.72rem;
        }}
        .action-btn {{
            color: var(--text-muted);
            padding: 6px 10px;
            border-radius: 4px;
            text-decoration: none;
            transition: color 0.2s, background 0.2s;
        }}
        .action-btn:hover {{
            color: var(--primary);
            background: #eef6fc;
        }}
        .empty-state {{
            display: none;
            text-align: center;
            padding: 40px;
            color: var(--text-muted);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fa-solid fa-folder-open"></i> {title}</h1>
            <a href="{home_href}" class="btn-back"><i class="fa-solid fa-arrow-left"></i> Home</a>
        </div>
        <p class="desc">{description}</p>
        
        <div class="search-container">
            <i class="fa-solid fa-magnifying-glass search-icon"></i>
            <input type="text" id="filterInput" class="search-input" placeholder="Search files (e.g. storage, brazilsouth, ipv4, 168)..." autofocus>
        </div>

        <div class="stats-bar">
            <span>Showing <strong id="visibleCount">{len(file_items)}</strong> of {len(file_items)} {badge_label.lower()}</span>
            <span>Compatible with: pfSense, OPNsense, Palo Alto, MikroTik, Fortinet</span>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Filename</th>
                    <th>Type</th>
                    <th>Records</th>
                    <th>Size</th>
                    <th style="width: 50px;">Action</th>
                </tr>
            </thead>
            <tbody id="fileTableBody">
                {''.join(file_items)}
            </tbody>
        </table>

        <div id="emptyState" class="empty-state">
            <i class="fa-solid fa-circle-question fa-2x" style="margin-bottom: 10px;"></i>
            <p>No matching files found.</p>
        </div>
    </div>

    <script>
        const input = document.getElementById('filterInput');
        const rows = document.querySelectorAll('.file-row');
        const visibleCount = document.getElementById('visibleCount');
        const emptyState = document.getElementById('emptyState');

        input.addEventListener('input', function() {{
            const term = this.value.trim().toLowerCase();
            let count = 0;

            rows.forEach(row => {{
                const name = row.getAttribute('data-name');
                if (!term || name.includes(term)) {{
                    row.style.display = '';
                    count++;
                }} else {{
                    row.style.display = 'none';
                }}
            }});

            visibleCount.textContent = count;
            emptyState.style.display = count === 0 ? 'block' : 'none';
        }});
    </script>
</body>
</html>"""
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)
        logging.info(f"Generated index.html for {directory} ({len(file_items)} files)")
    except Exception as e:
        logging.error(f"Failed to generate index.html for {directory}: {e}")
        raise

# ==========================================
# 1. AZURE UPDATER
# ==========================================

def fetch_azure_json_url() -> str:
    """Fetch the JSON URL from the Microsoft download confirmation page."""
    logging.info("Fetching the Azure JSON URL from Microsoft download page...")
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
    }
    response = requests.get(AZURE_DOWNLOAD_URL, headers=headers, timeout=30)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "html.parser")

    script_tag = soup.find("script", string=lambda t: bool(t and "window.__DLCDetails__" in t))
    if not script_tag or not script_tag.string:
        raise RuntimeError("Script tag containing JSON URL not found on Microsoft download page.")

    match = re.search(r'"url":"(https://download\.microsoft\.com/download/[^"]+\.json)"', script_tag.string)
    if not match:
        raise RuntimeError("JSON file download URL regex match failed in script tag.")

    json_url = match.group(1)
    logging.info(f"Azure JSON URL retrieved: {json_url}")
    return json_url

def update_azure() -> Dict[str, Any]:
    """Download, collapse, and generate IP ranges for Microsoft Azure."""
    logging.info("--- Starting Microsoft Azure update ---")
    json_url = fetch_azure_json_url()
    response = requests.get(json_url, timeout=60)
    response.raise_for_status()

    json_filename = os.path.basename(json_url)
    data = response.json()

    # Save to json-history
    target_json_path = os.path.join(JSON_DIR, json_filename)
    with open(target_json_path, "wb") as f:
        f.write(response.content)

    entries = data.get("values", [])

    # 1. Services
    service_names: Set[str] = set()
    for entry in entries:
        sys_service = entry.get("properties", {}).get("systemService")
        if sys_service:
            service_names.add(sys_service)
    service_names.add("AzureCloud")
    service_names.add("AzureFrontDoor.Frontend")
    service_names.add("AzureFrontDoor.Backend")

    for svc in sorted(service_names):
        if svc == "AzureCloud":
            prefixes = [p for entry in entries if entry.get("name") == "AzureCloud" for p in entry.get("properties", {}).get("addressPrefixes", [])]
        elif svc in ("AzureFrontDoor.Frontend", "AzureFrontDoor.Backend"):
            prefixes = [p for entry in entries if entry.get("name") == svc for p in entry.get("properties", {}).get("addressPrefixes", [])]
        else:
            prefixes = [p for entry in entries if entry.get("properties", {}).get("systemService") == svc or entry.get("name") == svc for p in entry.get("properties", {}).get("addressPrefixes", [])]

        v4, v6 = process_prefixes(prefixes)
        write_range_files(OUTPUT_SERVICES_DIR, svc, v4, v6)
        write_range_files(AZURE_SERVICES_DIR, svc, v4, v6)

    # 2. Regions
    regions: Set[str] = set()
    for entry in entries:
        reg = entry.get("properties", {}).get("region")
        if reg:
            regions.add(reg)

    for reg in sorted(regions):
        prefixes = [p for entry in entries if entry.get("properties", {}).get("region") == reg or entry.get("name") == f"AzureCloud.{reg}" for p in entry.get("properties", {}).get("addressPrefixes", [])]
        v4, v6 = process_prefixes(prefixes)
        write_range_files(OUTPUT_REGIONS_DIR, reg, v4, v6)
        write_range_files(AZURE_REGIONS_DIR, reg, v4, v6)

    # Static mirror
    static_ref = os.path.join(JSON_DIR, "ServiceTags_Public.json")
    shutil.copy2(target_json_path, static_ref)
    os.makedirs(AZURE_JSON_DIR, exist_ok=True)
    shutil.copy2(target_json_path, os.path.join(AZURE_JSON_DIR, "ServiceTags_Public.json"))

    # Apply 12-week retention
    apply_json_history_retention(JSON_DIR, RETENTION_WEEKS)
    apply_json_history_retention(AZURE_JSON_DIR, RETENTION_WEEKS)

    # Generate directory indices
    generate_directory_index(OUTPUT_SERVICES_DIR, os.path.join(OUTPUT_SERVICES_DIR, "index.html"), "Azure Services IP Ranges", "Automated, deduplicated CIDR lists by Azure service.", "Services")
    generate_directory_index(AZURE_SERVICES_DIR, os.path.join(AZURE_SERVICES_DIR, "index.html"), "Azure Services IP Ranges", "Automated, deduplicated CIDR lists by Azure service.", "Services")
    generate_directory_index(OUTPUT_REGIONS_DIR, os.path.join(OUTPUT_REGIONS_DIR, "index.html"), "Azure Regional IP Ranges", "Complete IP ranges aggregated per Azure Region.", "Regions")
    generate_directory_index(AZURE_REGIONS_DIR, os.path.join(AZURE_REGIONS_DIR, "index.html"), "Azure Regional IP Ranges", "Complete IP ranges aggregated per Azure Region.", "Regions")
    generate_directory_index(JSON_DIR, os.path.join(JSON_DIR, "index.html"), "Azure JSON Archive", "12-week rolling retention archive of Microsoft Azure Service Tags.", "Archives")
    generate_directory_index(AZURE_JSON_DIR, os.path.join(AZURE_JSON_DIR, "index.html"), "Azure JSON Archive", "12-week rolling retention archive of Microsoft Azure Service Tags.", "Archives")

    logging.info(f"Azure complete: {len(service_names)} services, {len(regions)} regions.")
    return {
        "services": len(service_names),
        "regions": len(regions),
        "change_number": data.get("changeNumber", "N/A"),
        "version_date": data.get("version", datetime.now(timezone.utc).strftime("%Y%m%d"))
    }

def apply_json_history_retention(json_dir: str, retention_weeks: int = 12) -> None:
    """Enforces a 12-week retention window on historical JSON dumps."""
    pattern = re.compile(r"^ServiceTags_Public_(\d{8})\.json(\.gz)?$")
    all_files = [f for f in os.listdir(json_dir) if pattern.match(f)]
    dates = sorted(set(pattern.match(f).group(1) for f in all_files), reverse=True)
    keep_dates = set(dates[:retention_weeks])

    for file in all_files:
        match = pattern.match(file)
        if match:
            date = match.group(1)
            file_path = os.path.join(json_dir, file)
            if date not in keep_dates:
                os.remove(file_path)
            elif not file.endswith(".gz"):
                gz_path = f"{file_path}.gz"
                with open(file_path, "rb") as f_in, gzip.open(gz_path, "wb", compresslevel=9) as f_out:
                    shutil.copyfileobj(f_in, f_out)
                os.remove(file_path)

# ==========================================
# 2. AWS UPDATER
# ==========================================

def update_aws() -> Dict[str, Any]:
    """Download, collapse, and generate IP ranges for Amazon Web Services (AWS)."""
    logging.info("--- Starting Amazon AWS update ---")
    response = requests.get(AWS_IP_RANGES_URL, timeout=30)
    response.raise_for_status()
    data = response.json()

    # Save static JSON mirror
    os.makedirs(AWS_JSON_DIR, exist_ok=True)
    json_path = os.path.join(AWS_JSON_DIR, "ip-ranges.json")
    with open(json_path, "wb") as f:
        f.write(response.content)

    prefixes_v4 = data.get("prefixes", [])
    prefixes_v6 = data.get("ipv6_prefixes", [])

    # 1. AWS Services
    services = set(p.get("service") for p in prefixes_v4 if p.get("service"))
    services.update(p.get("service") for p in prefixes_v6 if p.get("service"))

    for svc in sorted(services):
        raw_v4 = [p["ip_prefix"] for p in prefixes_v4 if p.get("service") == svc]
        raw_v6 = [p["ipv6_prefix"] for p in prefixes_v6 if p.get("service") == svc]
        v4, v6 = process_prefixes(raw_v4 + raw_v6)
        write_range_files(AWS_SERVICES_DIR, svc, v4, v6)

    # 2. AWS Regions
    regions = set(p.get("region") for p in prefixes_v4 if p.get("region"))
    regions.update(p.get("region") for p in prefixes_v6 if p.get("region"))

    for reg in sorted(regions):
        raw_v4 = [p["ip_prefix"] for p in prefixes_v4 if p.get("region") == reg]
        raw_v6 = [p["ipv6_prefix"] for p in prefixes_v6 if p.get("region") == reg]
        v4, v6 = process_prefixes(raw_v4 + raw_v6)
        write_range_files(AWS_REGIONS_DIR, reg, v4, v6)

    # Generate directory indices
    generate_directory_index(AWS_SERVICES_DIR, os.path.join(AWS_SERVICES_DIR, "index.html"), "AWS Services IP Ranges", "Automated, CIDR-collapsed lists for Amazon Web Services.", "Services")
    generate_directory_index(AWS_REGIONS_DIR, os.path.join(AWS_REGIONS_DIR, "index.html"), "AWS Regional IP Ranges", "Aggregated IP ranges for each AWS Region (e.g. sa-east-1, us-east-1).", "Regions")
    generate_directory_index(AWS_JSON_DIR, os.path.join(AWS_JSON_DIR, "index.html"), "AWS JSON Mirror", "Static mirror of Amazon AWS ip-ranges.json.", "Mirror")

    logging.info(f"AWS complete: {len(services)} services, {len(regions)} regions.")
    return {
        "services": len(services),
        "regions": len(regions),
        "sync_token": data.get("syncToken", "N/A")
    }

# ==========================================
# 3. GCP UPDATER
# ==========================================

def update_gcp() -> Dict[str, Any]:
    """Download, collapse, and generate IP ranges for Google Cloud Platform (GCP)."""
    logging.info("--- Starting Google Cloud (GCP) update ---")
    response = requests.get(GCP_IP_RANGES_URL, timeout=30)
    response.raise_for_status()
    data = response.json()

    # Save static JSON mirror
    os.makedirs(GCP_JSON_DIR, exist_ok=True)
    json_path = os.path.join(GCP_JSON_DIR, "cloud.json")
    with open(json_path, "wb") as f:
        f.write(response.content)

    entries = data.get("prefixes", [])

    # 1. GCP Scopes / Regions
    scopes = set(p.get("scope") for p in entries if p.get("scope"))
    for sc in sorted(scopes):
        raw = [p.get("ipv4Prefix") or p.get("ipv6Prefix") for p in entries if p.get("scope") == sc]
        v4, v6 = process_prefixes(raw)
        write_range_files(GCP_REGIONS_DIR, sc, v4, v6)

    # 2. All GCP prefixes (combined list)
    all_raw = [p.get("ipv4Prefix") or p.get("ipv6Prefix") for p in entries if p.get("ipv4Prefix") or p.get("ipv6Prefix")]
    all_v4, all_v6 = process_prefixes(all_raw)
    write_range_files(GCP_REGIONS_DIR, "GoogleCloud", all_v4, all_v6)

    # Generate directory indices
    generate_directory_index(GCP_REGIONS_DIR, os.path.join(GCP_REGIONS_DIR, "index.html"), "Google Cloud Regional IP Ranges", "Aggregated CIDR lists for GCP regions and global endpoints.", "Regions")
    generate_directory_index(GCP_JSON_DIR, os.path.join(GCP_JSON_DIR, "index.html"), "GCP JSON Mirror", "Static mirror of Google Cloud cloud.json.", "Mirror")

    logging.info(f"GCP complete: {len(scopes)} regions + GoogleCloud list.")
    return {
        "regions": len(scopes),
        "sync_token": data.get("syncToken", "N/A")
    }

# ==========================================
# 4. CLOUDFLARE UPDATER
# ==========================================

def update_cloudflare() -> Dict[str, Any]:
    """Download, collapse, and generate IP ranges for Cloudflare."""
    logging.info("--- Starting Cloudflare update ---")
    response = requests.get(CLOUDFLARE_IPS_URL, timeout=30)
    response.raise_for_status()
    data = response.json()

    os.makedirs(CF_JSON_DIR, exist_ok=True)
    json_path = os.path.join(CF_JSON_DIR, "cloudflare-ips.json")
    with open(json_path, "wb") as f:
        f.write(response.content)

    res = data.get("result", {})
    raw_v4 = res.get("ipv4_cidrs", [])
    raw_v6 = res.get("ipv6_cidrs", [])
    v4, v6 = process_prefixes(raw_v4 + raw_v6)

    write_range_files(CF_DIR, "cloudflare", v4, v6)
    generate_directory_index(CF_DIR, os.path.join(CF_DIR, "index.html"), "Cloudflare IP Ranges", "Cloudflare Anycast edge proxies, CDN, and WAF IP ranges.", "Files")

    logging.info(f"Cloudflare complete: {len(v4)} IPv4, {len(v6)} IPv6 CIDRs.")
    return {
        "ipv4_count": len(v4),
        "ipv6_count": len(v6)
    }

# ==========================================
# 5. ROOT INDEX GENERATOR
# ==========================================

def generate_root_index(
    azure_meta: Dict[str, Any],
    aws_meta: Dict[str, Any],
    gcp_meta: Dict[str, Any],
    cf_meta: Dict[str, Any]
) -> None:
    """Render templates/index_template.html into docs/index.html with multi-cloud stats."""
    logging.info("Generating root index.html...")
    with open(TEMPLATE_FILE, "r", encoding="utf-8") as f:
        template = f.read()

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    replacements = {
        "{{AZURE_SERVICES_COUNT}}": str(azure_meta.get("services", 100)),
        "{{AZURE_REGIONS_COUNT}}": str(azure_meta.get("regions", 78)),
        "{{AWS_SERVICES_COUNT}}": str(aws_meta.get("services", 27)),
        "{{AWS_REGIONS_COUNT}}": str(aws_meta.get("regions", 43)),
        "{{GCP_REGIONS_COUNT}}": str(gcp_meta.get("regions", 48)),
        "{{CF_V4_COUNT}}": str(cf_meta.get("ipv4_count", 15)),
        "{{CF_V6_COUNT}}": str(cf_meta.get("ipv6_count", 7)),
        "{{GENERATED_TIME}}": now_utc,
        "{{GENERATED_BY}}": "GitHub Actions Automation"
    }

    for key, val in replacements.items():
        template = template.replace(key, val)

    with open(INDEX_FILE, "w", encoding="utf-8") as f:
        f.write(template)

    logging.info(f"Root index.html saved to {INDEX_FILE}")

# ==========================================
# MAIN EXECUTION
# ==========================================

def main() -> None:
    logging.info("Starting Cloud IP Ranges Multi-Cloud Update...")
    ensure_directories()

    azure_meta = update_azure()
    aws_meta = update_aws()
    gcp_meta = update_gcp()
    cf_meta = update_cloudflare()

    generate_root_index(azure_meta, aws_meta, gcp_meta, cf_meta)
    logging.info("All clouds updated and synchronized successfully!")

if __name__ == "__main__":
    main()
