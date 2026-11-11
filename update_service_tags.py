import requests
from bs4 import BeautifulSoup
import json
import os
import re
import shutil
import gzip
import hashlib
import tarfile
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
SQUIDGUARD_UPSTREAM_URL = "https://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz"

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

# SquidGuard paths (UT1 Toulouse Contingency Mirror)
SQUIDGUARD_DIR = os.path.join(DOCS_DIR, "squidguard")
SQUIDGUARD_ARCHIVE_FILE = os.path.join(SQUIDGUARD_DIR, "blacklists.tar.gz")
SQUIDGUARD_SHA256_FILE = os.path.join(SQUIDGUARD_DIR, "blacklists.tar.gz.sha256")
SQUIDGUARD_INDEX_FILE = os.path.join(SQUIDGUARD_DIR, "index.html")
SQUIDGUARD_META_FILE = os.path.join(SQUIDGUARD_DIR, "meta.json")

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
        CF_JSON_DIR,
        SQUIDGUARD_DIR
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
            if not f.startswith('.') and f != os.path.basename(output_file) and f != "ip-index.json"
        ]

        rel_home = os.path.relpath(DOCS_DIR, directory)
        home_href = os.path.normpath(os.path.join(rel_home, "index.html")).replace("\\", "/")

        has_ip_files = False
        ip_index = {"ipv4": {}, "ipv6": {}}
        for file in files:
            file_path = os.path.join(directory, file)
            if not os.path.isfile(file_path):
                continue
            if file.endswith(".ipv4.txt"):
                has_ip_files = True
                base = file[:-9]
                with open(file_path, "r", encoding="utf-8") as rf:
                    ip_index["ipv4"][base] = [line.strip() for line in rf if line.strip()]
            elif file.endswith(".ipv6.txt"):
                has_ip_files = True
                base = file[:-9]
                with open(file_path, "r", encoding="utf-8") as rf:
                    ip_index["ipv6"][base] = [line.strip() for line in rf if line.strip()]

        if has_ip_files:
            ip_index_path = os.path.join(directory, "ip-index.json")
            with open(ip_index_path, "w", encoding="utf-8") as f:
                json.dump(ip_index, f)

        has_ip_files_js = "true" if has_ip_files else "false"

        file_items = []
        for file in files:
            file_path = os.path.join(directory, file)
            if not os.path.isfile(file_path):
                continue
            size = os.path.getsize(file_path)
            size_str = format_file_size(size)

            if file.endswith(".ipv4.txt"):
                tag_class = "tag-ipv4"
                tag_name = "IPv4"
                base_name = file[:-9]
                ip_type = "ipv4"
            elif file.endswith(".ipv6.txt"):
                tag_class = "tag-ipv6"
                tag_name = "IPv6"
                base_name = file[:-9]
                ip_type = "ipv6"
            elif file.endswith(".txt"):
                tag_class = "tag-all"
                tag_name = "ALL"
                base_name = file[:-4]
                ip_type = "both"
            elif file.endswith(".json.gz"):
                tag_class = "tag-gz"
                tag_name = "JSON.GZ"
                base_name = file
                ip_type = "other"
            elif file.endswith(".json"):
                tag_class = "tag-json"
                tag_name = "JSON"
                base_name = file
                ip_type = "other"
            else:
                tag_class = "tag-all"
                tag_name = "FILE"
                base_name = file
                ip_type = "other"

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
                f'<tr class="file-row" data-name="{search_data}" data-base="{base_name}" data-type="{ip_type}">'
                f'<td><div class="file-cell">'
                f'<a class="file-name" href="{file}">{file}</a>'
                f'<div class="match-info" style="display:none;"></div>'
                f'</div></td>'
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
        .header-actions {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .lang-switch {{
            display: inline-flex;
            align-items: center;
            background: #f1f5f9;
            padding: 3px;
            border-radius: 20px;
            border: 1px solid var(--border);
            gap: 2px;
        }}
        .lang-btn {{
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 4px 10px;
            border-radius: 14px;
            border: none;
            background: transparent;
            color: var(--text-muted);
            font-size: 0.8rem;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.2s ease;
            user-select: none;
        }}
        .lang-btn:hover {{
            color: var(--text);
        }}
        .lang-btn.active {{
            background: #ffffff;
            color: var(--primary);
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.08);
        }}
        .flag-icon {{
            font-size: 1rem;
            line-height: 1;
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
            margin-bottom: 12px;
            position: relative;
            display: flex;
            align-items: center;
        }}
        .search-input {{
            width: 100%;
            padding: 13px 44px 13px 44px;
            font-size: 0.95rem;
            border: 1px solid var(--border);
            border-radius: 6px;
            outline: none;
            transition: all 0.2s;
            background: #ffffff;
        }}
        .search-input:focus {{
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(0, 120, 212, 0.15);
        }}
        .search-icon {{
            position: absolute;
            left: 15px;
            color: var(--text-muted);
            font-size: 1rem;
            pointer-events: none;
        }}
        .clear-btn {{
            position: absolute;
            right: 12px;
            background: transparent;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            padding: 6px 8px;
            border-radius: 50%;
            font-size: 0.95rem;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.15s;
        }}
        .clear-btn:hover {{
            background: #eef2f5;
            color: #0f172a;
        }}
        .filter-status {{
            margin-bottom: 14px;
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.88rem;
            padding: 8px 14px;
            border-radius: 6px;
            animation: fadeIn 0.2s ease-in-out;
        }}
        .status-ip-v4 {{
            background: #ecfdf5;
            color: #065f46;
            border: 1px solid #a7f3d0;
        }}
        .status-ip-v6 {{
            background: #f5f3ff;
            color: #5b21b6;
            border: 1px solid #ddd6fe;
        }}
        .status-loading {{
            background: #eff6ff;
            color: #1d4ed8;
            border: 1px solid #bfdbfe;
        }}
        .file-cell {{
            display: flex;
            flex-direction: column;
            gap: 4px;
        }}
        .match-info {{
            display: inline-flex;
            flex-wrap: wrap;
            gap: 6px;
            margin-top: 3px;
        }}
        .match-pill {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.78rem;
            font-weight: 500;
            background: #ecfdf5;
            color: #065f46;
            border: 1px solid #a7f3d0;
        }}
        .match-pill code {{
            background: #d1fae5;
            color: #047857;
            padding: 1px 4px;
            border-radius: 3px;
            font-weight: 600;
            font-family: ui-monospace, SFMono-Regular, monospace;
        }}
        .match-pill-v6 {{
            background: #f5f3ff;
            color: #5b21b6;
            border-color: #ddd6fe;
        }}
        .match-pill-v6 code {{
            background: #ede9fe;
            color: #6d28d9;
        }}
        .stats-bar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.88rem;
            color: var(--text-muted);
            margin-bottom: 12px;
            flex-wrap: wrap;
            gap: 8px;
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
            <div class="header-actions">
                <div class="lang-switch">
                    <button type="button" class="lang-btn active" id="btn-lang-en" onclick="setLang('en')" title="Switch to English"><span class="flag-icon">🇺🇸</span> EN</button>
                    <button type="button" class="lang-btn" id="btn-lang-pt" onclick="setLang('pt')" title="Mudar para Português"><span class="flag-icon">🇧🇷</span> PT-BR</button>
                </div>
                <a href="{home_href}" class="btn-back"><i class="fa-solid fa-arrow-left"></i> <span data-i18n="back_home">Home</span></a>
            </div>
        </div>
        <p class="desc">{description}</p>
        
        <div class="search-container">
            <i class="fa-solid fa-magnifying-glass search-icon"></i>
            <input type="text" id="filterInput" class="search-input" placeholder="Filter by name or IP / CIDR address (e.g. storage, 20.38.106.12, 13.107.6.0/24)..." autofocus data-i18n-placeholder="search_placeholder">
            <button type="button" id="clearBtn" class="clear-btn" style="display:none;" title="Clear search" data-i18n-title="clear_search"><i class="fa-solid fa-xmark"></i></button>
        </div>
        <div id="filterStatus" class="filter-status" style="display: none;"></div>

        <div class="stats-bar">
            <span id="statsLabel">Showing <strong id="visibleCount">{len(file_items)}</strong> of {len(file_items)} {badge_label.lower()}</span>
            <span data-i18n="compatible_firewalls"><i class="fa-solid fa-shield-halved"></i> Compatible with: pfSense, OPNsense, Palo Alto, MikroTik, Fortinet</span>
        </div>

        <table>
            <thead>
                <tr>
                    <th><span data-i18n="th_filename">Filename</span></th>
                    <th><span data-i18n="th_type">Type</span></th>
                    <th><span data-i18n="th_records">Records</span></th>
                    <th><span data-i18n="th_size">Size</span></th>
                    <th style="width: 50px;"><span data-i18n="th_action">Action</span></th>
                </tr>
            </thead>
            <tbody id="fileTableBody">
                {''.join(file_items)}
            </tbody>
        </table>

        <div id="emptyState" class="empty-state">
            <i class="fa-solid fa-circle-question fa-2x" style="margin-bottom: 10px;"></i>
            <p id="emptyMsg" data-i18n="empty_msg">No matching files found.</p>
        </div>
    </div>

    <script>
        const DIR_I18N = {{
            en: {{
                back_home: "Home",
                search_placeholder: "Filter by name or IP / CIDR address (e.g. storage, 20.38.106.12, 13.107.6.0/24)...",
                clear_search: "Clear search",
                compatible_firewalls: '<i class="fa-solid fa-shield-halved"></i> Compatible with: pfSense, OPNsense, Palo Alto, MikroTik, Fortinet',
                th_filename: "Filename",
                th_type: "Type",
                th_records: "Records",
                th_size: "Size",
                th_action: "Action",
                empty_msg: "No matching files found.",
                stats_showing: (vis, tot, label) => `Showing <strong id="visibleCount">${{vis}}</strong> of ${{tot}} ${{label}}`,
                loading_ips: '<i class="fa-solid fa-spinner fa-spin"></i> Loading IP database for lookup...',
                contains_label: "Contains:",
                prefix_label: "Prefix:",
                more_label: "more",
                ipv4_detected: "IPv4 Address detected:",
                cidr4_detected: "IPv4 CIDR Block detected:",
                ipv6_detected: "IPv6 Address detected:",
                cidr6_detected: "IPv6 CIDR Block detected:",
                prefix_detected: "IP Prefix detected:",
                showing_containing: "Showing lists containing",
                showing_prefix: "Showing lists with prefixes starting with",
                matched_suffix: "lists matched",
                empty_ip_msg: (term) => `No lists on this page contain the IP/CIDR block <strong>${{term}}</strong>.`,
                empty_prefix_msg: (term) => `No lists found for prefix "${{term}}".`,
                empty_text_msg: (term) => `No files found matching "${{term}}".`
            }},
            pt: {{
                back_home: "Início",
                search_placeholder: "Buscar por nome ou endereço IP / CIDR (ex: storage, 20.38.106.12, 13.107.6.0/24)...",
                clear_search: "Limpar busca",
                compatible_firewalls: '<i class="fa-solid fa-shield-halved"></i> Compatível com: pfSense, OPNsense, Palo Alto, MikroTik, Fortinet',
                th_filename: "Nome do Arquivo",
                th_type: "Tipo",
                th_records: "Registros",
                th_size: "Tamanho",
                th_action: "Ação",
                empty_msg: "Nenhum arquivo encontrado.",
                stats_showing: (vis, tot, label) => `Mostrando <strong id="visibleCount">${{vis}}</strong> de ${{tot}} ${{label}}`,
                loading_ips: '<i class="fa-solid fa-spinner fa-spin"></i> Carregando base de IPs para consulta...',
                contains_label: "Contém:",
                prefix_label: "Prefixo:",
                more_label: "mais",
                ipv4_detected: "Endereço IPv4 detectado:",
                cidr4_detected: "Bloco CIDR IPv4 detectado:",
                ipv6_detected: "Endereço IPv6 detectado:",
                cidr6_detected: "Bloco CIDR IPv6 detectado:",
                prefix_detected: "Prefixo IP detectado:",
                showing_containing: "Mostrando listas que contêm",
                showing_prefix: "Mostrando listas com blocos iniciando em",
                matched_suffix: "listas encontradas",
                empty_ip_msg: (term) => `Nenhuma lista nesta página contém o IP/bloco <strong>${{term}}</strong>.`,
                empty_prefix_msg: (term) => `Nenhuma lista encontrada para o prefixo "${{term}}".`,
                empty_text_msg: (term) => `Nenhum arquivo encontrado para "${{term}}".`
            }}
        }};

        let currentLang = localStorage.getItem('cloud_ip_lang') || 'en';

        function setLang(lang) {{
            currentLang = lang;
            localStorage.setItem('cloud_ip_lang', lang);

            const btnEn = document.getElementById('btn-lang-en');
            const btnPt = document.getElementById('btn-lang-pt');
            if (btnEn && btnPt) {{
                btnEn.classList.toggle('active', lang === 'en');
                btnPt.classList.toggle('active', lang === 'pt');
            }}

            const dict = DIR_I18N[lang] || DIR_I18N.en;
            document.querySelectorAll('[data-i18n]').forEach(el => {{
                const key = el.getAttribute('data-i18n');
                if (dict[key]) {{
                    el.innerHTML = dict[key];
                }}
            }});
            document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {{
                const key = el.getAttribute('data-i18n-placeholder');
                if (dict[key]) {{
                    el.placeholder = dict[key];
                }}
            }});
            document.querySelectorAll('[data-i18n-title]').forEach(el => {{
                const key = el.getAttribute('data-i18n-title');
                if (dict[key]) {{
                    el.title = dict[key];
                }}
            }});

            runFilter();
        }}

        const input = document.getElementById('filterInput');
        const clearBtn = document.getElementById('clearBtn');
        const filterStatus = document.getElementById('filterStatus');
        const rows = document.querySelectorAll('.file-row');
        const visibleCount = document.getElementById('visibleCount');
        const emptyState = document.getElementById('emptyState');
        const emptyMsg = document.getElementById('emptyMsg');
        const hasIpIndex = {has_ip_files_js};
        const totalItemsCount = {len(file_items)};
        const badgeLabel = "{badge_label.lower()}";

        let ipIndex = null;
        let parsedIndex = {{ ipv4: {{}}, ipv6: {{}} }};
        let ipIndexLoaded = false;
        let ipIndexLoading = false;

        function parseIpv4(ipStr) {{
            const parts = ipStr.trim().split('.');
            if (parts.length !== 4) return null;
            let num = 0;
            for (let i = 0; i < 4; i++) {{
                const n = parseInt(parts[i], 10);
                if (isNaN(n) || n < 0 || n > 255 || parts[i] !== String(n)) return null;
                num = ((num << 8) + n) >>> 0;
            }}
            return num;
        }}

        function parseIpv6(ipStr) {{
            let str = ipStr.trim().toLowerCase();
            if (!str.includes(':')) return null;
            let parts = str.split('::');
            if (parts.length > 2) return null;
            let left = parts[0] ? parts[0].split(':') : [];
            let right = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
            let totalParts = left.length + right.length;
            if (parts.length === 1 && totalParts !== 8) return null;
            if (parts.length === 2 && totalParts > 7) return null;
            let missing = 8 - totalParts;
            let full = [...left, ...Array(missing).fill('0'), ...right];
            let big = 0n;
            for (let p of full) {{
                if (!/^[0-9a-f]{{1,4}}$/.test(p)) return null;
                big = (big << 16n) + BigInt(parseInt(p, 16));
            }}
            return big;
        }}

        function parseCidr4(cidrStr) {{
            const idx = cidrStr.indexOf('/');
            const ipPart = idx === -1 ? cidrStr : cidrStr.slice(0, idx);
            const ip = parseIpv4(ipPart);
            if (ip === null) return null;
            const bits = idx === -1 ? 32 : parseInt(cidrStr.slice(idx + 1), 10);
            if (isNaN(bits) || bits < 0 || bits > 32) return null;
            const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
            const net = (ip & mask) >>> 0;
            return {{ net, mask, bits, raw: cidrStr }};
        }}

        function parseCidr6(cidrStr) {{
            const idx = cidrStr.indexOf('/');
            const ipPart = idx === -1 ? cidrStr : cidrStr.slice(0, idx);
            const ip = parseIpv6(ipPart);
            if (ip === null) return null;
            const bits = idx === -1 ? 128 : parseInt(cidrStr.slice(idx + 1), 10);
            if (isNaN(bits) || bits < 0 || bits > 128) return null;
            const mask = bits === 0 ? 0n : ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - bits)) - 1n);
            const net = ip & mask;
            return {{ net, mask, bits, raw: cidrStr }};
        }}

        function matchCidrs4(query, listCidr) {{
            if (query.bits === 32) {{
                return ((query.net & listCidr.mask) >>> 0) === listCidr.net;
            }}
            if (listCidr.bits <= query.bits) {{
                return ((query.net & listCidr.mask) >>> 0) === listCidr.net;
            }}
            return ((listCidr.net & query.mask) >>> 0) === query.net;
        }}

        function matchCidrs6(query, listCidr) {{
            if (query.bits === 128) {{
                return (query.net & listCidr.mask) === listCidr.net;
            }}
            if (listCidr.bits <= query.bits) {{
                return (query.net & listCidr.mask) === listCidr.net;
            }}
            return (listCidr.net & query.mask) === query.net;
        }}

        function preParseIndex() {{
            if (!ipIndex) return;
            if (ipIndex.ipv4) {{
                for (const [base, cidrs] of Object.entries(ipIndex.ipv4)) {{
                    parsedIndex.ipv4[base] = [];
                    for (let i = 0; i < cidrs.length; i++) {{
                        const p = parseCidr4(cidrs[i]);
                        if (p) parsedIndex.ipv4[base].push(p);
                    }}
                }}
            }}
            if (ipIndex.ipv6) {{
                for (const [base, cidrs] of Object.entries(ipIndex.ipv6)) {{
                    parsedIndex.ipv6[base] = [];
                    for (let i = 0; i < cidrs.length; i++) {{
                        const p = parseCidr6(cidrs[i]);
                        if (p) parsedIndex.ipv6[base].push(p);
                    }}
                }}
            }}
        }}

        if (hasIpIndex) {{
            ipIndexLoading = true;
            fetch('ip-index.json')
                .then(r => {{
                    if (r.ok) return r.json();
                    throw new Error('Not found');
                }})
                .then(data => {{
                    ipIndex = data;
                    preParseIndex();
                    ipIndexLoaded = true;
                    ipIndexLoading = false;
                    if (input.value.trim()) {{
                        runFilter();
                    }}
                }})
                .catch(err => {{
                    ipIndexLoading = false;
                    console.log('IP index not available:', err);
                }});
        }}

        function runFilter() {{
            const rawTerm = input.value.trim();
            clearBtn.style.display = rawTerm ? 'flex' : 'none';
            const dict = DIR_I18N[currentLang] || DIR_I18N.en;
            const statsLabel = document.getElementById('statsLabel');

            if (!rawTerm) {{
                filterStatus.style.display = 'none';
                rows.forEach(row => {{
                    row.style.display = '';
                    const matchInfo = row.querySelector('.match-info');
                    if (matchInfo) matchInfo.style.display = 'none';
                }});
                if (statsLabel) statsLabel.innerHTML = dict.stats_showing(rows.length, totalItemsCount, badgeLabel);
                emptyState.style.display = 'none';
                return;
            }}

            let isIpv4 = false;
            let isIpv6 = false;
            let queryCidr4 = null;
            let queryCidr6 = null;

            if (rawTerm.includes(':')) {{
                queryCidr6 = parseCidr6(rawTerm);
                if (queryCidr6) isIpv6 = true;
            }} else if (/^\\d{{1,3}}(\\.\\d{{1,3}}){{1,3}}(\\/\\d{{1,2}})?$/.test(rawTerm)) {{
                queryCidr4 = parseCidr4(rawTerm);
                if (queryCidr4) isIpv4 = true;
            }}

            // 1. Full IPv4 / CIDR query
            if (isIpv4 && hasIpIndex) {{
                if (ipIndexLoading) {{
                    filterStatus.className = 'filter-status status-loading';
                    filterStatus.innerHTML = dict.loading_ips;
                    filterStatus.style.display = 'flex';
                    return;
                }}
                const matches = {{}};
                for (const [base, list] of Object.entries(parsedIndex.ipv4)) {{
                    for (let i = 0; i < list.length; i++) {{
                        if (matchCidrs4(queryCidr4, list[i])) {{
                            if (!matches[base]) matches[base] = [];
                            matches[base].push(list[i].raw);
                        }}
                    }}
                }}

                let count = 0;
                rows.forEach(row => {{
                    const base = row.getAttribute('data-base');
                    const type = row.getAttribute('data-type');
                    const matchInfo = row.querySelector('.match-info');

                    if (matches[base] && (type === 'ipv4' || type === 'both')) {{
                        row.style.display = '';
                        count++;
                        if (matchInfo) {{
                            const topCidrs = matches[base].slice(0, 3);
                            const more = matches[base].length > 3 ? ` +${{matches[base].length - 3}} ${{dict.more_label}}` : '';
                            matchInfo.innerHTML = `<span class=\"match-pill\"><i class=\"fa-solid fa-check-circle\"></i> ${{dict.contains_label}} <code>${{topCidrs.join(', ')}}${{more}}</code></span>`;
                            matchInfo.style.display = 'inline-flex';
                        }}
                    }} else {{
                        row.style.display = 'none';
                        if (matchInfo) matchInfo.style.display = 'none';
                    }}
                }});

                filterStatus.className = 'filter-status status-ip-v4';
                const kind = queryCidr4.bits === 32 ? dict.ipv4_detected : dict.cidr4_detected;
                filterStatus.innerHTML = `<i class=\"fa-solid fa-filter\"></i> <strong>${{kind}}</strong> ${{dict.showing_containing}} <code>${{escapeHtml(rawTerm)}}</code> (${{Object.keys(matches).length}} ${{dict.matched_suffix}})`;
                filterStatus.style.display = 'flex';

                if (statsLabel) statsLabel.innerHTML = dict.stats_showing(count, totalItemsCount, badgeLabel);
                emptyMsg.innerHTML = dict.empty_ip_msg(escapeHtml(rawTerm));
                emptyState.style.display = count === 0 ? 'block' : 'none';
                return;
            }}

            // 2. Full IPv6 / CIDR query
            if (isIpv6 && hasIpIndex) {{
                if (ipIndexLoading) {{
                    filterStatus.className = 'filter-status status-loading';
                    filterStatus.innerHTML = dict.loading_ips;
                    filterStatus.style.display = 'flex';
                    return;
                }}
                const matches = {{}};
                for (const [base, list] of Object.entries(parsedIndex.ipv6)) {{
                    for (let i = 0; i < list.length; i++) {{
                        if (matchCidrs6(queryCidr6, list[i])) {{
                            if (!matches[base]) matches[base] = [];
                            matches[base].push(list[i].raw);
                        }}
                    }}
                }}

                let count = 0;
                rows.forEach(row => {{
                    const base = row.getAttribute('data-base');
                    const type = row.getAttribute('data-type');
                    const matchInfo = row.querySelector('.match-info');

                    if (matches[base] && (type === 'ipv6' || type === 'both')) {{
                        row.style.display = '';
                        count++;
                        if (matchInfo) {{
                            const topCidrs = matches[base].slice(0, 3);
                            const more = matches[base].length > 3 ? ` +${{matches[base].length - 3}} ${{dict.more_label}}` : '';
                            matchInfo.innerHTML = `<span class=\"match-pill match-pill-v6\"><i class=\"fa-solid fa-check-circle\"></i> ${{dict.contains_label}} <code>${{topCidrs.join(', ')}}${{more}}</code></span>`;
                            matchInfo.style.display = 'inline-flex';
                        }}
                    }} else {{
                        row.style.display = 'none';
                        if (matchInfo) matchInfo.style.display = 'none';
                    }}
                }});

                filterStatus.className = 'filter-status status-ip-v6';
                const kind = queryCidr6.bits === 128 ? dict.ipv6_detected : dict.cidr6_detected;
                filterStatus.innerHTML = `<i class=\"fa-solid fa-filter\"></i> <strong>${{kind}}</strong> ${{dict.showing_containing}} <code>${{escapeHtml(rawTerm)}}</code> (${{Object.keys(matches).length}} ${{dict.matched_suffix}})`;
                filterStatus.style.display = 'flex';

                if (statsLabel) statsLabel.innerHTML = dict.stats_showing(count, totalItemsCount, badgeLabel);
                emptyMsg.innerHTML = dict.empty_ip_msg(escapeHtml(rawTerm));
                emptyState.style.display = count === 0 ? 'block' : 'none';
                return;
            }}

            // 3. Partial IP prefix match (e.g. "20.38." or "52.239.152")
            if (/^\\d{{1,3}}(\\.\\d{{1,3}}){{1,2}}\\.?$/.test(rawTerm) && hasIpIndex && ipIndexLoaded) {{
                const prefix = rawTerm.endsWith('.') ? rawTerm : rawTerm + '.';
                const matches = {{}};
                for (const [base, list] of Object.entries(parsedIndex.ipv4)) {{
                    for (let i = 0; i < list.length; i++) {{
                        if (list[i].raw.startsWith(rawTerm) || list[i].raw.startsWith(prefix)) {{
                            if (!matches[base]) matches[base] = [];
                            matches[base].push(list[i].raw);
                        }}
                    }}
                }}

                if (Object.keys(matches).length > 0) {{
                    let count = 0;
                    rows.forEach(row => {{
                        const base = row.getAttribute('data-base');
                        const type = row.getAttribute('data-type');
                        const matchInfo = row.querySelector('.match-info');

                        if (matches[base] && (type === 'ipv4' || type === 'both')) {{
                            row.style.display = '';
                            count++;
                            if (matchInfo) {{
                                const topCidrs = matches[base].slice(0, 3);
                                const more = matches[base].length > 3 ? ` +${{matches[base].length - 3}} ${{dict.more_label}}` : '';
                                matchInfo.innerHTML = `<span class=\"match-pill\"><i class=\"fa-solid fa-magnifying-glass\"></i> ${{dict.prefix_label}} <code>${{topCidrs.join(', ')}}${{more}}</code></span>`;
                                matchInfo.style.display = 'inline-flex';
                            }}
                        }} else {{
                            row.style.display = 'none';
                            if (matchInfo) matchInfo.style.display = 'none';
                        }}
                    }});

                    filterStatus.className = 'filter-status status-ip-v4';
                    filterStatus.innerHTML = `<i class=\"fa-solid fa-filter\"></i> <strong>${{dict.prefix_detected}}</strong> ${{dict.showing_prefix}} <code>${{escapeHtml(rawTerm)}}</code> (${{Object.keys(matches).length}} ${{dict.matched_suffix}})`;
                    filterStatus.style.display = 'flex';

                    if (statsLabel) statsLabel.innerHTML = dict.stats_showing(count, totalItemsCount, badgeLabel);
                    emptyMsg.innerHTML = dict.empty_prefix_msg(escapeHtml(rawTerm));
                    emptyState.style.display = count === 0 ? 'block' : 'none';
                    return;
                }}
            }}

            // 4. Standard text search on filename and records
            filterStatus.style.display = 'none';
            const termLower = rawTerm.toLowerCase();
            let count = 0;
            rows.forEach(row => {{
                const name = row.getAttribute('data-name');
                const matchInfo = row.querySelector('.match-info');
                if (matchInfo) matchInfo.style.display = 'none';

                if (name && name.includes(termLower)) {{
                    row.style.display = '';
                    count++;
                }} else {{
                    row.style.display = 'none';
                }}
            }});

            if (statsLabel) statsLabel.innerHTML = dict.stats_showing(count, totalItemsCount, badgeLabel);
            emptyMsg.innerHTML = dict.empty_text_msg(escapeHtml(rawTerm));
            emptyState.style.display = count === 0 ? 'block' : 'none';
        }}

        function escapeHtml(str) {{
            return String(str).replace(/[&<>"']/g, m => ({{ '&': '&amp;', '<': '&lt;', '>': '&gt;', '\"': '&quot;', \"'\": '&#39;' }}[m]));
        }}

        input.addEventListener('input', runFilter);
        clearBtn.addEventListener('click', () => {{
            input.value = '';
            runFilter();
            input.focus();
        }});

        // Initialize language
        setLang(currentLang);
    </script>
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
# 5. SQUIDGUARD BLACKLIST CONTINGENCY MIRROR
# ==========================================

def generate_squidguard_index(meta: Dict[str, Any]) -> None:
    """Generate docs/squidguard/index.html detailing the UT1 Toulouse SquidGuard mirror."""
    os.makedirs(SQUIDGUARD_DIR, exist_ok=True)

    categories = meta.get("categories", [])
    cat_count = meta.get("category_count", len(categories))
    size_mb = meta.get("size_mb", 25.38)
    sha256 = meta.get("sha256", "")
    updated_at = meta.get("updated_at", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))

    categories_html = "".join([f'<span class="cat-pill"><i class="fa-solid fa-tag"></i> {cat}</span>' for cat in categories])

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SquidGuard Web Filter Blacklists — Shallalist Successor Mirror (UT1 Capitole)</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
    <style>
        :root {{
            --primary: #0284c7;
            --primary-dark: #0369a1;
            --primary-light: #e0f2fe;
            --accent: #2563eb;
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --text: #1e293b;
            --text-muted: #64748b;
            --border: #e2e8f0;
            --radius: 10px;
            --shadow: 0 4px 14px rgba(0, 0, 0, 0.05);
        }}

        * {{
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 30px 16px;
            background-color: var(--bg);
            color: var(--text);
        }}

        .container {{
            max-width: 1080px;
            margin: 0 auto;
            background-color: var(--card-bg);
            padding: 36px;
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            border: 1px solid var(--border);
        }}

        .top-nav-bar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 12px;
        }}

        .nav-back {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            color: var(--primary);
            text-decoration: none;
            font-weight: 600;
            font-size: 0.95rem;
            padding: 6px 12px;
            border-radius: 6px;
            background: #f1f5f9;
            transition: all 0.2s;
        }}

        .nav-back:hover {{
            background: #e2e8f0;
            color: var(--primary-dark);
            text-decoration: none;
        }}

        .lang-switch {{
            display: inline-flex;
            align-items: center;
            background: #f1f5f9;
            padding: 3px;
            border-radius: 20px;
            border: 1px solid var(--border);
            gap: 2px;
        }}

        .lang-btn {{
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 4px 10px;
            border-radius: 14px;
            border: none;
            background: transparent;
            color: var(--text-muted);
            font-size: 0.8rem;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.2s ease;
            user-select: none;
        }}

        .lang-btn:hover {{
            color: var(--text);
        }}

        .lang-btn.active {{
            background: #ffffff;
            color: var(--primary);
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.08);
        }}

        .flag-icon {{
            font-size: 1rem;
            line-height: 1;
        }}

        .header {{
            border-bottom: 2px solid #f1f5f9;
            padding-bottom: 22px;
            margin-bottom: 24px;
        }}

        .header-top {{
            display: flex;
            align-items: center;
            gap: 16px;
            margin-bottom: 10px;
        }}

        .header-top i {{
            font-size: 2.4rem;
            color: var(--primary);
        }}

        .header h1 {{
            margin: 0;
            font-size: 1.85rem;
            color: #0f172a;
            font-weight: 700;
        }}

        .badges-bar {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 10px;
        }}

        .badge {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
        }}

        .badge-mirror {{ background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe; }}
        .badge-univ {{ background: #fef3c7; color: #92400e; border: 1px solid #fde68a; }}
        .badge-pfsense {{ background: #ecfdf5; color: #047857; border: 1px solid #a7f3d0; }}

        .attribution-box {{
            background: #fffbeb;
            border: 1px solid #fcd34d;
            border-left: 6px solid #f59e0b;
            padding: 16px 20px;
            border-radius: 8px;
            margin: 24px 0;
            color: #78350f;
            font-size: 0.95rem;
        }}

        .attribution-box strong {{
            color: #92400e;
        }}

        .direct-download-card {{
            background: linear-gradient(145deg, #f8fafc, #edf2f7);
            border: 1px solid #cbd5e1;
            border-radius: 10px;
            padding: 24px;
            margin-bottom: 30px;
        }}

        .url-row {{
            margin: 16px 0;
        }}

        .url-row label {{
            display: block;
            font-weight: 700;
            font-size: 0.88rem;
            color: #334155;
            margin-bottom: 6px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .url-input-group {{
            display: flex;
            gap: 8px;
        }}

        .url-input-group input {{
            flex: 1;
            padding: 12px 14px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: 0.95rem;
            border: 1px solid #94a3b8;
            border-radius: 6px;
            background: #ffffff;
            color: #0f172a;
        }}

        .btn-copy {{
            background: var(--primary);
            color: #ffffff;
            border: none;
            border-radius: 6px;
            padding: 0 20px;
            font-weight: 600;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: background 0.2s;
        }}

        .btn-copy:hover {{
            background: var(--primary-dark);
        }}

        .meta-stats {{
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            margin-top: 16px;
            font-size: 0.88rem;
            color: #475569;
        }}

        .meta-stats span {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: #ffffff;
            padding: 6px 12px;
            border-radius: 6px;
            border: 1px solid #e2e8f0;
        }}

        .action-buttons {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 18px;
        }}

        .btn-action {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 18px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 0.92rem;
            text-decoration: none;
            transition: all 0.2s;
        }}

        .btn-action-primary {{
            background: #0284c7;
            color: #ffffff;
        }}

        .btn-action-primary:hover {{
            background: #0369a1;
            color: #ffffff;
            text-decoration: none;
        }}

        .btn-action-secondary {{
            background: #ffffff;
            color: #334155;
            border: 1px solid #cbd5e1;
        }}

        .btn-action-secondary:hover {{
            background: #f1f5f9;
            color: #0f172a;
            text-decoration: none;
        }}

        .section-title {{
            font-size: 1.35rem;
            color: #0f172a;
            margin: 32px 0 16px 0;
            display: flex;
            align-items: center;
            gap: 10px;
            border-bottom: 2px solid #f1f5f9;
            padding-bottom: 10px;
        }}

        .guide-steps {{
            padding-left: 20px;
            margin: 16px 0;
        }}

        .guide-steps li {{
            margin-bottom: 14px;
            line-height: 1.6;
        }}

        code {{
            background: #f1f5f9;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: ui-monospace, SFMono-Regular, monospace;
            font-size: 0.88rem;
            color: #be123c;
        }}

        .categories-filter-box {{
            margin: 20px 0 14px 0;
            display: flex;
            gap: 12px;
            align-items: center;
        }}

        .categories-filter-box input {{
            flex: 1;
            padding: 9px 14px;
            border: 1px solid #cbd5e1;
            border-radius: 6px;
            font-size: 0.9rem;
        }}

        .categories-container {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            max-height: 340px;
            overflow-y: auto;
            padding: 12px;
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
        }}

        .cat-pill {{
            background: #ffffff;
            border: 1px solid #cbd5e1;
            padding: 4px 10px;
            border-radius: 14px;
            font-size: 0.82rem;
            color: #334155;
            font-family: ui-monospace, SFMono-Regular, monospace;
            transition: all 0.15s;
        }}

        .cat-pill:hover {{
            border-color: var(--primary);
            color: var(--primary);
            background: #f0f9ff;
        }}

        .tip-callout {{
            background: #ecfdf5;
            border-left: 4px solid #10b981;
            padding: 14px 18px;
            border-radius: 6px;
            margin-top: 16px;
            color: #065f46;
            font-size: 0.92rem;
        }}

        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #f1f5f9;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
            color: var(--text-muted);
            font-size: 0.88rem;
        }}

        a {{
            color: var(--primary);
            text-decoration: none;
        }}

        a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="top-nav-bar">
            <a href="../index.html" class="nav-back"><i class="fa-solid fa-arrow-left"></i> <span data-i18n="back_hub">Back to Cloud IP Ranges Hub</span></a>
            <div class="lang-switch">
                <button type="button" class="lang-btn active" id="btn-lang-en" onclick="setLang('en')" title="Switch to English"><span class="flag-icon">🇺🇸</span> EN</button>
                <button type="button" class="lang-btn" id="btn-lang-pt" onclick="setLang('pt')" title="Mudar para Português"><span class="flag-icon">🇧🇷</span> PT-BR</button>
            </div>
        </div>

        <div class="header">
            <div class="header-top">
                <i class="fa-solid fa-shield-cat"></i>
                <div>
                    <h1>SquidGuard Web Filter Blacklists</h1>
                    <p style="margin: 4px 0 0 0; color: var(--text-muted); font-size: 0.98rem;" data-i18n="sg_subtitle">
                        Automated Contingency Mirror (Shallalist Successor Mirror) for pfSense, Squid, and SquidGuard
                    </p>
                </div>
            </div>
            <div class="badges-bar">
                <span class="badge badge-mirror" data-i18n="badge_mirror"><i class="fa-solid fa-cloud-arrow-down"></i> Contingency Mirror</span>
                <span class="badge badge-univ" data-i18n="badge_univ"><i class="fa-solid fa-building-columns"></i> Official Curation: Université Toulouse 1 Capitole</span>
                <span class="badge badge-pfsense" data-i18n="badge_compat"><i class="fa-solid fa-shield-halved"></i> 100% Compatible with pfSense & SquidGuard</span>
            </div>
        </div>

        <!-- Attribution Box -->
        <div class="attribution-box">
            <p style="margin: 0 0 8px 0; font-weight: 700;" data-i18n="attr_title">
                <i class="fa-solid fa-circle-info"></i> Official Credits & Purpose of this Mirror:
            </p>
            <p style="margin: 0;" data-i18n="attr_desc">
                This database is officially maintained and cataloged by the <strong>Direction des Systèmes d'Information of Université Toulouse 1 Capitole (France)</strong>. This repository acts strictly as an <strong>automated contingency mirror (Shallalist Successor Mirror)</strong> to ensure redundancy and protect network administrators against service downtime and future abandonment (as historically occurred with Shallalist). All categorization credits and intellectual property belong entirely to the University of Toulouse.
            </p>
        </div>

        <!-- Direct Ingestion Card -->
        <div class="direct-download-card">
            <div class="url-row">
                <label for="sgUrlInput" data-i18n="lbl_direct_url"><i class="fa-solid fa-link"></i> Direct URL for Ingestion in pfSense / SquidGuard:</label>
                <div class="url-input-group">
                    <input type="text" id="sgUrlInput" readonly value="https://leoescarpellin.github.io/cloudIPrange/squidguard/blacklists.tar.gz">
                    <button class="btn-copy" onclick="copyUrl()"><i class="fa-regular fa-copy"></i> <span data-i18n="btn_copy">Copy URL</span></button>
                </div>
            </div>

            <div class="meta-stats">
                <span><i class="fa-solid fa-hard-drive"></i> <span data-i18n="meta_size">Size:</span> <strong>{size_mb} MB</strong></span>
                <span><i class="fa-solid fa-tags"></i> <span data-i18n="meta_cats">Categories:</span> <strong>{cat_count}</strong></span>
                <span><i class="fa-solid fa-clock"></i> <span data-i18n="meta_synced">Synchronized:</span> <strong>{updated_at}</strong></span>
                <span><i class="fa-solid fa-fingerprint"></i> SHA-256: <code>{sha256[:16]}...</code></span>
            </div>

            <div class="action-buttons">
                <a href="blacklists.tar.gz" class="btn-action btn-action-primary"><i class="fa-solid fa-download"></i> <span data-i18n="btn_dl">Download blacklists.tar.gz ({size_mb} MB)</span></a>
                <a href="blacklists.tar.gz.sha256" class="btn-action btn-action-secondary" target="_blank"><i class="fa-solid fa-file-shield"></i> <span data-i18n="btn_view_sha">View SHA-256 Checksum</span></a>
                <a href="https://dsi.ut-capitole.fr/blacklists/" class="btn-action btn-action-secondary" target="_blank" rel="noopener"><i class="fa-solid fa-arrow-up-right-from-square"></i> <span data-i18n="btn_upstream">Official Upstream (UT1 Capitole)</span></a>
            </div>
        </div>

        <!-- pfSense Setup Instructions -->
        <h2 class="section-title"><i class="fa-solid fa-screwdriver-wrench"></i> <span data-i18n="guide_title">How to Configure in pfSense (Step-by-Step)</span></h2>
        <div id="guideStepsContainer">
            <ol class="guide-steps" id="guideStepsList">
                <li>In the pfSense WebGUI menu, navigate to <strong>Services &rarr; SquidGuard Proxy Filter</strong>.</li>
                <li>In the <strong>General Settings</strong> tab, make sure SquidGuard is enabled (<strong>Enable</strong>).</li>
                <li>Navigate to the <strong>Blacklist</strong> tab:
                    <ul>
                        <li>Check the <strong>Blacklist</strong> checkbox (Enable blacklist).</li>
                        <li>In the <strong>Blacklist URL</strong> field, paste this mirror URL:  
                            <code>https://leoescarpellin.github.io/cloudIPrange/squidguard/blacklists.tar.gz</code>
                        </li>
                    </ul>
                </li>
                <li>Scroll to the bottom of the page and click <strong>Save</strong>.</li>
                <li>Switch to the <strong>Blacklist update</strong> tab and click the <strong>Download</strong> button. pfSense will download the archive, extract to <code>/var/db/squidGuard/</code>, and compile Berkeley DB tables (<code>.db</code>). Wait until the message reports <i>Blacklist update complete</i>.</li>
                <li>Go to the <strong>Common ACL</strong> tab (or configure group ACLs in <strong>Group ACL</strong>) and click the <strong>+</strong> icon under <strong>Target Rules List</strong>:
                    <ul>
                        <li>Define desired actions for each category (e.g. <code>deny</code> for <i>malware</i>, <i>phishing</i>, <i>adult</i>, <i>cryptojacking</i>, etc.).</li>
                    </ul>
                </li>
                <li>Click <strong>Save</strong> at the bottom of the page.</li>
                <li>Return to the <strong>General Settings</strong> tab and click <strong>Apply</strong> at the top of the screen to activate the new filtering rules in the live proxy.</li>
            </ol>
        </div>

        <div class="tip-callout" data-i18n="tip_cron">
            <i class="fa-solid fa-lightbulb"></i> <strong>Performance & Cron Tip:</strong>  
            You can automate weekly blacklist updates in pfSense by configuring a scheduled job in the <strong>Cron</strong> package (e.g. running the SquidGuard download/update command on Sundays or Mondays) ensuring continuous protection without manual intervention.
        </div>

        <!-- Available Categories -->
        <h2 class="section-title"><i class="fa-solid fa-folder-tree"></i> <span id="catHeaderTitle">Included Categories ({cat_count} Categories)</span></h2>
        <div class="categories-filter-box">
            <i class="fa-solid fa-magnifying-glass" style="color: var(--text-muted);"></i>
            <input type="text" id="catSearchInput" placeholder="Filter categories (e.g. malware, social, games, adult)..." onkeyup="filterCategories()" data-i18n-placeholder="search_cats">
        </div>
        <div class="categories-container" id="catContainer">
            {categories_html}
        </div>

        <!-- Footer -->
        <div class="footer">
            <div>
                <span data-i18n="footer_credits">Contingency Mirror maintained by the <a href="https://github.com/leoescarpellin/cloudIPrange" target="_blank">cloudIPrange</a> project</span>
            </div>
            <div>
                <a href="../index.html"><i class="fa-solid fa-arrow-left"></i> <span data-i18n="footer_back">Return to Main Hub</span></a>
            </div>
        </div>
    </div>

    <script>
        const SG_I18N = {{
            en: {{
                back_hub: "Back to Cloud IP Ranges Hub",
                sg_subtitle: "Automated Contingency Mirror (Shallalist Successor Mirror) for pfSense, Squid, and SquidGuard",
                badge_mirror: '<i class="fa-solid fa-cloud-arrow-down"></i> Contingency Mirror',
                badge_univ: '<i class="fa-solid fa-building-columns"></i> Official Curation: Université Toulouse 1 Capitole',
                badge_compat: '<i class="fa-solid fa-shield-halved"></i> 100% Compatible with pfSense & SquidGuard',
                attr_title: '<i class="fa-solid fa-circle-info"></i> Official Credits & Purpose of this Mirror:',
                attr_desc: "This database is officially maintained and cataloged by the <strong>Direction des Systèmes d\\'Information of Université Toulouse 1 Capitole (France)</strong>. This repository acts strictly as an <strong>automated contingency mirror (Shallalist Successor Mirror)</strong> to ensure redundancy and protect network administrators against service downtime and future abandonment (as historically occurred with Shallalist). All categorization credits and intellectual property belong entirely to the University of Toulouse.",
                lbl_direct_url: '<i class="fa-solid fa-link"></i> Direct URL for Ingestion in pfSense / SquidGuard:',
                btn_copy: "Copy URL",
                btn_copied: '<i class="fa-solid fa-check"></i> Copied!',
                meta_size: "Size:",
                meta_cats: "Categories:",
                meta_synced: "Synchronized:",
                btn_dl: "Download blacklists.tar.gz ({size_mb} MB)",
                btn_view_sha: "View SHA-256 Checksum",
                btn_upstream: "Official Upstream (UT1 Capitole)",
                guide_title: "How to Configure in pfSense (Step-by-Step)",
                guide_steps: [
                    "In the pfSense WebGUI menu, navigate to <strong>Services &rarr; SquidGuard Proxy Filter</strong>.",
                    "In the <strong>General Settings</strong> tab, make sure SquidGuard is enabled (<strong>Enable</strong>).",
                    "Navigate to the <strong>Blacklist</strong> tab:<ul><li>Check the <strong>Blacklist</strong> checkbox (Enable blacklist).</li><li>In the <strong>Blacklist URL</strong> field, paste this mirror URL: <code>https://leoescarpellin.github.io/cloudIPrange/squidguard/blacklists.tar.gz</code></li></ul>",
                    "Scroll to the bottom of the page and click <strong>Save</strong>.",
                    "Switch to the <strong>Blacklist update</strong> tab and click the <strong>Download</strong> button. pfSense will download the archive, extract to <code>/var/db/squidGuard/</code>, and compile Berkeley DB tables (<code>.db</code>). Wait until the message reports <i>Blacklist update complete</i>.",
                    "Go to the <strong>Common ACL</strong> tab (or configure group ACLs in <strong>Group ACL</strong>) and click the <strong>+</strong> icon under <strong>Target Rules List</strong>:<ul><li>Define desired actions for each category (e.g. <code>deny</code> for <i>malware</i>, <i>phishing</i>, <i>adult</i>, <i>cryptojacking</i>, etc.).</li></ul>",
                    "Click <strong>Save</strong> at the bottom of the page.",
                    "Return to the <strong>General Settings</strong> tab and click <strong>Apply</strong> at the top of the screen to activate the new filtering rules in the live proxy."
                ],
                tip_cron: '<i class="fa-solid fa-lightbulb"></i> <strong>Performance & Cron Tip:</strong> You can automate weekly blacklist updates in pfSense by configuring a scheduled job in the <strong>Cron</strong> package (e.g. running the SquidGuard download/update command on Sundays or Mondays) ensuring continuous protection without manual intervention.',
                cat_header: "Included Categories ({cat_count} Categories)",
                search_cats: "Filter categories (e.g. malware, social, games, adult)...",
                footer_credits: 'Contingency Mirror maintained by the <a href="https://github.com/leoescarpellin/cloudIPrange" target="_blank">cloudIPrange</a> project',
                footer_back: "Return to Main Hub"
            }},
            pt: {{
                back_hub: "Voltar ao Hub Cloud IP Ranges",
                sg_subtitle: "Espelho Automatizado de Contingência (Shallalist Successor Mirror) para pfSense, Squid e SquidGuard",
                badge_mirror: '<i class="fa-solid fa-cloud-arrow-down"></i> Mirror de Contingência',
                badge_univ: '<i class="fa-solid fa-building-columns"></i> Curadoria Oficial: Université Toulouse 1 Capitole',
                badge_compat: '<i class="fa-solid fa-shield-halved"></i> 100% Compatível com pfSense & SquidGuard',
                attr_title: '<i class="fa-solid fa-circle-info"></i> Créditos Oficiais & Finalidade deste Espelho:',
                attr_desc: "Esta base de dados é mantida e catalogada oficialmente pela <strong>Direction des Systèmes d\\'Information da Université Toulouse 1 Capitole (França)</strong>. Este repositório atua estritamente como um <strong>espelho automatizado de contingência (Shallalist Successor Mirror)</strong> para assegurar redundância e blindar administradores de redes contra indisponibilidades e abandono futuro de repositórios (como ocorrido historicamente com a Shallalist). Todos os créditos de catalogação e propriedade intelectual pertencem integralmente à Universidade de Toulouse.",
                lbl_direct_url: '<i class="fa-solid fa-link"></i> URL Direta para Ingestão no pfSense / SquidGuard:',
                btn_copy: "Copiar URL",
                btn_copied: '<i class="fa-solid fa-check"></i> Copiado!',
                meta_size: "Tamanho:",
                meta_cats: "Categorias:",
                meta_synced: "Sincronizado:",
                btn_dl: "Baixar blacklists.tar.gz ({size_mb} MB)",
                btn_view_sha: "Ver Checksum SHA-256",
                btn_upstream: "Upstream Oficial (UT1 Capitole)",
                guide_title: "Como Configurar no pfSense (Passo a Passo)",
                guide_steps: [
                    "No menu do pfSense WebGUI, acesse <strong>Services &rarr; SquidGuard Proxy Filter</strong>.",
                    "Na aba <strong>General Settings</strong>, certifique-se de que o SquidGuard está habilitado (<strong>Enable</strong>).",
                    "Navegue até a aba <strong>Blacklist</strong>:<ul><li>Marque a caixa de seleção <strong>Blacklist</strong> (Enable blacklist).</li><li>No campo <strong>Blacklist URL</strong>, cole a URL deste mirror: <code>https://leoescarpellin.github.io/cloudIPrange/squidguard/blacklists.tar.gz</code></li></ul>",
                    "Role até o final da página e clique em <strong>Save</strong>.",
                    "Acesse a aba <strong>Blacklist update</strong> e clique no botão <strong>Download</strong>. O pfSense fará o download do arquivo, descompactará em <code>/var/db/squidGuard/</code> e compilará as tabelas Berkeley DB (<code>.db</code>). Aguarde até a mensagem de conclusão (<i>Blacklist update complete</i>).",
                    "Acesse a aba <strong>Common ACL</strong> (ou configure ACLs por grupo em <strong>Group ACL</strong>) e clique no ícone <strong>+</strong> em <strong>Target Rules List</strong>:<ul><li>Defina a ação desejada para cada categoria (ex: <code>deny</code> para <i>malware</i>, <i>phishing</i>, <i>adult</i>, <i>cryptojacking</i>, etc.).</li></ul>",
                    "Clique em <strong>Save</strong> no final da página.",
                    "Retorne à aba <strong>General Settings</strong> e clique em <strong>Apply</strong> no topo da tela para carregar as novas regras no proxy ativo."
                ],
                tip_cron: '<i class="fa-solid fa-lightbulb"></i> <strong>Dica de Desempenho & Cron:</strong> Você pode automatizar a atualização semanal da blacklist no pfSense configurando um agendamento no pacote <strong>Cron</strong> (ex: executando o comando de download/update do SquidGuard aos domingos ou segundas-feiras) para que seu ambiente permaneça protegido sem intervenção manual.',
                cat_header: "Categorias Incluídas ({cat_count} Categorias)",
                search_cats: "Filtrar categorias (ex: malware, social, games, adult)...",
                footer_credits: 'Espelho de Contingência mantido no projeto <a href="https://github.com/leoescarpellin/cloudIPrange" target="_blank">cloudIPrange</a>',
                footer_back: "Retornar ao Hub Principal"
            }}
        }};

        let currentLang = localStorage.getItem('cloud_ip_lang') || 'en';

        function setLang(lang) {{
            currentLang = lang;
            localStorage.setItem('cloud_ip_lang', lang);

            const btnEn = document.getElementById('btn-lang-en');
            const btnPt = document.getElementById('btn-lang-pt');
            if (btnEn && btnPt) {{
                btnEn.classList.toggle('active', lang === 'en');
                btnPt.classList.toggle('active', lang === 'pt');
            }}

            const dict = SG_I18N[lang] || SG_I18N.en;
            document.querySelectorAll('[data-i18n]').forEach(el => {{
                const key = el.getAttribute('data-i18n');
                if (dict[key]) {{
                    el.innerHTML = dict[key];
                }}
            }});
            document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {{
                const key = el.getAttribute('data-i18n-placeholder');
                if (dict[key]) {{
                    el.placeholder = dict[key];
                }}
            }});

            const catHeader = document.getElementById('catHeaderTitle');
            if (catHeader) {{
                catHeader.textContent = dict.cat_header;
            }}

            const stepsList = document.getElementById('guideStepsList');
            if (stepsList && dict.guide_steps) {{
                stepsList.innerHTML = dict.guide_steps.map(s => `<li>${{s}}</li>`).join('');
            }}
        }}

        function copyUrl() {{
            const input = document.getElementById("sgUrlInput");
            input.select();
            input.setSelectionRange(0, 99999);
            navigator.clipboard.writeText(input.value).then(() => {{
                const btn = document.querySelector(".btn-copy");
                const dict = SG_I18N[currentLang] || SG_I18N.en;
                btn.innerHTML = dict.btn_copied;
                setTimeout(() => {{
                    btn.innerHTML = '<i class="fa-regular fa-copy"></i> ' + dict.btn_copy;
                }}, 2000);
            }});
        }}

        function filterCategories() {{
            const filter = document.getElementById("catSearchInput").value.toLowerCase();
            const pills = document.querySelectorAll(".cat-pill");
            pills.forEach(pill => {{
                const text = pill.textContent.toLowerCase();
                if (text.includes(filter)) {{
                    pill.style.display = "inline-flex";
                }} else {{
                    pill.style.display = "none";
                }}
            }});
        }}

        // Initialize language
        setLang(currentLang);
    </script>
</body>
</html>
"""
    with open(SQUIDGUARD_INDEX_FILE, "w", encoding="utf-8") as f:
        f.write(html_content)
    logging.info(f"SquidGuard index.html generated at {SQUIDGUARD_INDEX_FILE}")

def update_squidguard() -> Dict[str, Any]:
    """
    Mirror the SquidGuard Web Filter Blacklist archive from Université Toulouse 1 Capitole.
    Acts as an automated contingency backup mirror (Shallalist successor).
    Validates integrity, generates SHA256 checksum, and produces an index.html guide.
    """
    logging.info("--- Starting SquidGuard Blacklist update ---")
    os.makedirs(SQUIDGUARD_DIR, exist_ok=True)

    meta: Dict[str, Any] = {}
    if os.path.exists(SQUIDGUARD_META_FILE):
        try:
            with open(SQUIDGUARD_META_FILE, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except Exception:
            pass

    headers = {}
    if os.path.exists(SQUIDGUARD_ARCHIVE_FILE) and meta.get("last_modified"):
        headers["If-Modified-Since"] = meta["last_modified"]

    download_needed = True
    try:
        head_resp = requests.head(SQUIDGUARD_UPSTREAM_URL, headers=headers, timeout=20)
        if head_resp.status_code == 304 and os.path.exists(SQUIDGUARD_ARCHIVE_FILE):
            logging.info("SquidGuard archive has not changed upstream (304 Not Modified). Reusing local mirror.")
            download_needed = False
    except Exception as e:
        logging.warning(f"Could not verify upstream HEAD: {e}")

    if download_needed or not os.path.exists(SQUIDGUARD_ARCHIVE_FILE):
        logging.info(f"Downloading SquidGuard archive from {SQUIDGUARD_UPSTREAM_URL}...")
        resp = requests.get(SQUIDGUARD_UPSTREAM_URL, stream=True, timeout=120)
        resp.raise_for_status()

        last_modified = resp.headers.get("Last-Modified", "")
        temp_file = os.path.join(TEMP_DIR, "blacklists.tar.gz")
        hasher = hashlib.sha256()
        total_size = 0

        with open(temp_file, "wb") as f:
            for chunk in resp.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)
                    hasher.update(chunk)
                    total_size += len(chunk)

        if total_size < 1_000_000:
            raise ValueError(f"Downloaded SquidGuard archive is suspiciously small: {total_size} bytes")

        shutil.move(temp_file, SQUIDGUARD_ARCHIVE_FILE)
        sha256_hash = hasher.hexdigest()

        # Write .sha256 file
        with open(SQUIDGUARD_SHA256_FILE, "w", encoding="utf-8") as f:
            f.write(f"{sha256_hash}  blacklists.tar.gz\n")

        # Inspect categories
        categories = []
        try:
            with tarfile.open(SQUIDGUARD_ARCHIVE_FILE, mode="r:gz") as tar:
                cat_names = set()
                for member in tar.getmembers():
                    parts = member.name.split("/")
                    if len(parts) > 1 and parts[1]:
                        item = parts[1]
                        if not item.endswith((".pdf", ".txt", ".md")) and item != "README":
                            cat_names.add(item)
                categories = sorted(list(cat_names))
        except Exception as e:
            logging.warning(f"Could not parse categories list from tar: {e}")

        size_mb = round(total_size / (1024 * 1024), 2)
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        meta = {
            "last_modified": last_modified,
            "sha256": sha256_hash,
            "size_bytes": total_size,
            "size_mb": size_mb,
            "category_count": len(categories),
            "categories": categories,
            "updated_at": now_utc
        }

        with open(SQUIDGUARD_META_FILE, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

    generate_squidguard_index(meta)

    logging.info(
        f"SquidGuard complete: {meta.get('size_mb', 0)} MB, "
        f"{meta.get('category_count', 0)} categories, SHA256: {meta.get('sha256', '')[:12]}..."
    )
    return meta

# ==========================================
# 6. GLOBAL MULTI-CLOUD IP LOOKUP INDEX
# ==========================================

def generate_global_ip_lookup() -> None:
    """Generate consolidated multi-cloud IP index for the global home page lookup."""
    logging.info("Generating global multi-cloud IP lookup index...")
    targets = [
        ("Azure Services", OUTPUT_SERVICES_DIR, "ranges-services/"),
        ("Azure Regions", OUTPUT_REGIONS_DIR, "ranges-regions/"),
        ("AWS Services", AWS_SERVICES_DIR, "aws/ranges-services/"),
        ("AWS Regions", AWS_REGIONS_DIR, "aws/ranges-regions/"),
        ("GCP Regions", GCP_REGIONS_DIR, "gcp/ranges-regions/"),
        ("Cloudflare", CF_DIR, "cloudflare/")
    ]

    lookup_data = {}
    for label, folder, url_prefix in targets:
        if not os.path.exists(folder):
            continue
        group = {"url": url_prefix, "v4": {}, "v6": {}}
        for f in os.listdir(folder):
            p = os.path.join(folder, f)
            if not os.path.isfile(p):
                continue
            if f.endswith(".ipv4.txt"):
                base = f[:-9]
                with open(p, "r", encoding="utf-8") as rf:
                    group["v4"][base] = [l.strip() for l in rf if l.strip()]
            elif f.endswith(".ipv6.txt"):
                base = f[:-9]
                with open(p, "r", encoding="utf-8") as rf:
                    group["v6"][base] = [l.strip() for l in rf if l.strip()]
        lookup_data[label] = group

    out_path = os.path.join(DOCS_DIR, "ip-lookup.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(lookup_data, f)
    logging.info(f"Global ip-lookup.json generated at {out_path} ({os.path.getsize(out_path) // 1024} KB)")

# ==========================================
# 7. ROOT INDEX GENERATOR
# ==========================================

def generate_root_index(
    azure_meta: Dict[str, Any],
    aws_meta: Dict[str, Any],
    gcp_meta: Dict[str, Any],
    cf_meta: Dict[str, Any],
    squidguard_meta: Dict[str, Any]
) -> None:
    """Render templates/index_template.html into docs/index.html with multi-cloud and SquidGuard stats."""
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
        "{{SQUIDGUARD_SIZE_MB}}": str(squidguard_meta.get("size_mb", "25.38")),
        "{{SQUIDGUARD_CATEGORIES_COUNT}}": str(squidguard_meta.get("category_count", "78")),
        "{{SQUIDGUARD_HASH_SHORT}}": str(squidguard_meta.get("sha256", ""))[:16],
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
    logging.info("Starting Cloud IP Ranges & SquidGuard Multi-Cloud Update...")
    ensure_directories()

    azure_meta = update_azure()
    aws_meta = update_aws()
    gcp_meta = update_gcp()
    cf_meta = update_cloudflare()
    squidguard_meta = update_squidguard()

    generate_global_ip_lookup()
    generate_root_index(azure_meta, aws_meta, gcp_meta, cf_meta, squidguard_meta)
    logging.info("All clouds and SquidGuard mirror updated and synchronized successfully!")

if __name__ == "__main__":
    main()
