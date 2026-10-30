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
URL = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
RETENTION_WEEKS = 12

DOCS_DIR = "docs"
TEMP_DIR = "docs_temp"

TEMP_SERVICES_DIR = os.path.join(TEMP_DIR, "ranges-services")
TEMP_REGIONS_DIR = os.path.join(TEMP_DIR, "ranges-regions")
TEMP_JSON_DIR = os.path.join(TEMP_DIR, "json-history")

OUTPUT_SERVICES_DIR = os.path.join(DOCS_DIR, "ranges-services")
OUTPUT_REGIONS_DIR = os.path.join(DOCS_DIR, "ranges-regions")
JSON_DIR = os.path.join(DOCS_DIR, "json-history")

TEMPLATE_FILE = "templates/index_template.html"
TEMP_INDEX_FILE = os.path.join(TEMP_DIR, "index.html")
INDEX_FILE = os.path.join(DOCS_DIR, "index.html")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

def ensure_directories() -> None:
    """Ensure all required directories exist and are writable."""
    directories = [
        DOCS_DIR,
        TEMP_DIR,
        TEMP_SERVICES_DIR,
        TEMP_REGIONS_DIR,
        TEMP_JSON_DIR,
        OUTPUT_SERVICES_DIR,
        OUTPUT_REGIONS_DIR,
        JSON_DIR
    ]
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            test_file = os.path.join(directory, '.test_write_perm')
            with open(test_file, 'w', encoding='utf-8') as f:
                f.write('test')
            os.remove(test_file)
            logging.debug(f"Verified write permissions for: {directory}")
        except Exception as e:
            logging.error(f"Error initializing directory {directory}: {e}")
            raise

def fetch_latest_json_url() -> str:
    """Fetch the JSON URL from the Microsoft download confirmation page."""
    logging.info("Fetching the JSON URL from the Microsoft download page...")
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
    }
    response = requests.get(URL, headers=headers, timeout=30)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "html.parser")

    script_tag = soup.find("script", string=lambda t: bool(t and "window.__DLCDetails__" in t))
    if not script_tag or not script_tag.string:
        raise RuntimeError("Script tag containing JSON URL not found on Microsoft download page.")

    match = re.search(r'"url":"(https://download\.microsoft\.com/download/[^"]+\.json)"', script_tag.string)
    if not match:
        raise RuntimeError("JSON file download URL regex match failed in script tag.")

    json_url = match.group(1)
    logging.info(f"JSON URL successfully retrieved: {json_url}")
    return json_url

def download_json(json_url: str) -> Tuple[str, str]:
    """Download the JSON file from Microsoft to the temporary JSON directory."""
    logging.info(f"Downloading JSON file from: {json_url}")
    response = requests.get(json_url, timeout=60)
    response.raise_for_status()

    json_filename = os.path.basename(json_url)
    json_path = os.path.join(TEMP_JSON_DIR, json_filename)

    with open(json_path, "wb") as f:
        f.write(response.content)

    if not os.path.exists(json_path):
        raise FileNotFoundError(f"JSON file was not saved to {json_path}")

    file_size_mb = os.path.getsize(json_path) / (1024 * 1024)
    logging.info(f"JSON file saved to: {json_path} ({file_size_mb:.2f} MB)")
    return json_filename, json_path

def process_prefixes(prefixes: Iterable[str]) -> Tuple[List[str], List[str]]:
    """
    Deduplicate and sort prefixes into IPv4 and IPv6 CIDRs.
    Sorted by numerical network address, then prefix length.
    """
    v4_set: Set[str] = set()
    v6_set: Set[str] = set()

    for p in prefixes:
        p = p.strip()
        if not p:
            continue
        if ":" in p:
            v6_set.add(p)
        else:
            v4_set.add(p)

    sorted_v4 = sorted(
        v4_set,
        key=lambda c: (
            int(ipaddress.IPv4Network(c, strict=False).network_address),
            ipaddress.IPv4Network(c, strict=False).prefixlen
        )
    )

    sorted_v6 = sorted(
        v6_set,
        key=lambda c: (
            int(ipaddress.IPv6Network(c, strict=False).network_address),
            ipaddress.IPv6Network(c, strict=False).prefixlen
        )
    )

    return sorted_v4, sorted_v6

def write_range_files(target_dir: str, name: str, v4_list: List[str], v6_list: List[str]) -> None:
    """
    Writes:
      - <name>.txt       -> combined IPv4 + IPv6 (sorted)
      - <name>.ipv4.txt  -> IPv4 only (if present)
      - <name>.ipv6.txt  -> IPv6 only (if present)
    """
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

def process_json(json_path: str) -> Dict[str, Any]:
    """
    Process the JSON file:
      - Extract and deduplicate IP ranges by service (with IPv4, IPv6 and combined files)
      - Extract and deduplicate IP ranges by region (with IPv4, IPv6 and combined files)
    """
    logging.info(f"Processing JSON file: {json_path}")
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    entries = data.get("values", [])

    # 1. Collect all services
    service_names: Set[str] = set()
    for entry in entries:
        props = entry.get("properties", {})
        sys_service = props.get("systemService")
        if sys_service:
            service_names.add(sys_service)

    # Add special root/standalone services
    service_names.add("AzureCloud")
    service_names.add("AzureFrontDoor.Frontend")
    service_names.add("AzureFrontDoor.Backend")

    logging.info(f"Generating range files for {len(service_names)} services...")
    for svc in sorted(service_names):
        if svc == "AzureCloud":
            prefixes = [
                p for entry in entries
                if entry.get("name") == "AzureCloud"
                for p in entry.get("properties", {}).get("addressPrefixes", [])
            ]
        elif svc in ("AzureFrontDoor.Frontend", "AzureFrontDoor.Backend"):
            prefixes = [
                p for entry in entries
                if entry.get("name") == svc
                for p in entry.get("properties", {}).get("addressPrefixes", [])
            ]
        else:
            prefixes = [
                p for entry in entries
                if entry.get("properties", {}).get("systemService") == svc or entry.get("name") == svc
                for p in entry.get("properties", {}).get("addressPrefixes", [])
            ]

        v4_list, v6_list = process_prefixes(prefixes)
        write_range_files(TEMP_SERVICES_DIR, svc, v4_list, v6_list)

    # 2. Collect all regions
    regions: Set[str] = set()
    for entry in entries:
        reg = entry.get("properties", {}).get("region")
        if reg:
            regions.add(reg)

    logging.info(f"Generating range files for {len(regions)} regions...")
    for reg in sorted(regions):
        # Union of AzureCloud.<region> and all regional service tags
        prefixes = [
            p for entry in entries
            if entry.get("properties", {}).get("region") == reg or entry.get("name") == f"AzureCloud.{reg}"
            for p in entry.get("properties", {}).get("addressPrefixes", [])
        ]

        v4_list, v6_list = process_prefixes(prefixes)
        # Write clean regional format (<region>.txt, <region>.ipv4.txt, <region>.ipv6.txt)
        write_range_files(TEMP_REGIONS_DIR, reg, v4_list, v6_list)

    change_number = data.get("changeNumber", "N/A")
    version = str(change_number)
    version_date = data.get("version", datetime.now(timezone.utc).strftime("%Y%m%d"))
    cloud = data.get("cloud", "Public")

    logging.info(
        f"Processing complete: {len(service_names)} services, "
        f"{len(regions)} regions (ChangeNumber: {change_number}, Cloud: {cloud})"
    )

    return {
        "total_services": len(service_names),
        "total_regions": len(regions),
        "change_number": change_number,
        "version": version,
        "version_date": version_date,
        "cloud": cloud
    }

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

        file_items = []
        for file in files:
            file_path = os.path.join(directory, file)
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

            file_items.append(
                f'<tr class="file-row" data-name="{file.lower()}">'
                f'<td><a class="file-name" href="{file}">{file}</a></td>'
                f'<td><span class="badge {tag_class}">{tag_name}</span></td>'
                f'<td class="file-size">{size_str}</td>'
                f'<td><a class="action-btn" href="{file}" download title="Download file"><i class="fa-solid fa-download"></i></a></td>'
                f'</tr>'
            )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} – Azure IP Ranges</title>
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
            <a href="../index.html" class="btn-back"><i class="fa-solid fa-arrow-left"></i> Home</a>
        </div>
        <p class="desc">{description}</p>
        
        <div class="search-container">
            <i class="fa-solid fa-magnifying-glass search-icon"></i>
            <input type="text" id="filterInput" class="search-input" placeholder="Search files (e.g. storage, brazilsouth, ipv4)..." autofocus>
        </div>

        <div class="stats-bar">
            <span>Showing <strong id="visibleCount">{len(files)}</strong> of {len(files)} {badge_label.lower()}</span>
            <span>Compatible with: pfSense, OPNsense, Palo Alto, MikroTik, Fortinet</span>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Filename</th>
                    <th>Type</th>
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
        logging.info(f"Generated index.html for {directory} ({len(files)} files)")
    except Exception as e:
        logging.error(f"Failed to generate index.html for {directory}: {e}")
        raise

def apply_json_history_retention(json_dir: str, retention_weeks: int = 12) -> None:
    """
    Enforces a retention window on historical JSON dumps:
      - Keeps the latest `retention_weeks` weekly files.
      - Compresses kept historical files to .json.gz (level 9) to minimize storage.
      - Removes files older than the retention window.
      - Leaves `ServiceTags_Public.json` uncompressed as the latest static reference.
    """
    pattern = re.compile(r"^ServiceTags_Public_(\d{8})\.json(\.gz)?$")
    all_files = [f for f in os.listdir(json_dir) if pattern.match(f)]

    dates = sorted(set(pattern.match(f).group(1) for f in all_files), reverse=True)
    keep_dates = set(dates[:retention_weeks])
    remove_dates = set(dates[retention_weeks:])

    logging.info(
        f"Applying JSON retention: keeping {len(keep_dates)} recent weeks, "
        f"pruning {len(remove_dates)} older weeks."
    )

    # 1. Prune older files outside the retention window
    for file in all_files:
        match = pattern.match(file)
        if match and match.group(1) in remove_dates:
            file_path = os.path.join(json_dir, file)
            try:
                os.remove(file_path)
                logging.debug(f"Pruned historical file: {file}")
            except Exception as e:
                logging.warning(f"Failed to remove {file_path}: {e}")

    # 2. Compress kept historical files to .json.gz and remove uncompressed duplicates
    for d in keep_dates:
        json_file = os.path.join(json_dir, f"ServiceTags_Public_{d}.json")
        gz_file = os.path.join(json_dir, f"ServiceTags_Public_{d}.json.gz")
        if os.path.exists(json_file):
            if not os.path.exists(gz_file):
                with open(json_file, "rb") as f_in:
                    content = f_in.read()
                with gzip.open(gz_file, "wb", compresslevel=9) as f_out:
                    f_out.write(content)
                logging.info(f"Compressed historical dump: {os.path.basename(gz_file)}")
            os.remove(json_file)

def update_index_page(
    version: str,
    version_date: str,
    json_filename: str,
    change_number: Any,
    total_services: int,
    total_regions: int
) -> None:
    """Update the root index.html page using the template."""
    if not os.path.exists(TEMPLATE_FILE):
        raise FileNotFoundError(f"Template file {TEMPLATE_FILE} not found.")

    with open(TEMPLATE_FILE, "r", encoding="utf-8") as tf:
        template_content = tf.read()

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Compressed specific filename for latest weekly archive
    gz_filename = f"{os.path.splitext(json_filename)[0]}.json.gz"

    updated_content = template_content.replace("{{LATEST_STATIC_JSON}}", f"json-history/{gz_filename}")
    updated_content = updated_content.replace("{{JSON_HISTORY_PATH}}", "json-history/")
    updated_content = updated_content.replace("{{SERVICES_PATH}}", "ranges-services/")
    updated_content = updated_content.replace("{{REGIONS_PATH}}", "ranges-regions/")
    updated_content = updated_content.replace("{{VERSION}}", str(version))
    updated_content = updated_content.replace("{{VERSION_DATE}}", str(version_date))
    updated_content = updated_content.replace("{{CHANGE_NUMBER}}", str(change_number))
    updated_content = updated_content.replace("{{TOTAL_SERVICES}}", str(total_services))
    updated_content = updated_content.replace("{{TOTAL_REGIONS}}", str(total_regions))
    updated_content = updated_content.replace("{{GENERATED_TIME}}", now_utc)
    updated_content = updated_content.replace("{{GENERATED_BY}}", "GitHub Actions Automation")

    with open(TEMP_INDEX_FILE, "w", encoding="utf-8") as index_file:
        index_file.write(updated_content)

    logging.info(f"Root index page updated and saved to temporary file: {TEMP_INDEX_FILE}")

def finalize_output(json_path: str, json_filename: str) -> None:
    """Move temporary processed files into docs/ and update indices."""
    logging.info("Finalizing output files into docs/ ...")

    # 1. Copy JSON files
    latest_json_path = os.path.join(JSON_DIR, "ServiceTags_Public.json")
    shutil.copy2(json_path, latest_json_path)

    weekly_json_path = os.path.join(JSON_DIR, json_filename)
    shutil.copy2(json_path, weekly_json_path)
    logging.info(f"Copied latest static JSON reference to {latest_json_path}")

    # Enforce 12-week retention and Gzip compression on historical dumps
    apply_json_history_retention(JSON_DIR, retention_weeks=RETENTION_WEEKS)

    # 2. Copy services directory
    if os.path.exists(TEMP_SERVICES_DIR):
        if os.path.exists(OUTPUT_SERVICES_DIR):
            shutil.rmtree(OUTPUT_SERVICES_DIR)
        shutil.copytree(TEMP_SERVICES_DIR, OUTPUT_SERVICES_DIR)
        logging.info(f"Copied Services TXT files to {OUTPUT_SERVICES_DIR}")

    # 3. Copy regions directory
    if os.path.exists(TEMP_REGIONS_DIR):
        if os.path.exists(OUTPUT_REGIONS_DIR):
            shutil.rmtree(OUTPUT_REGIONS_DIR)
        shutil.copytree(TEMP_REGIONS_DIR, OUTPUT_REGIONS_DIR)
        logging.info(f"Copied Regions TXT files to {OUTPUT_REGIONS_DIR}")

    # 4. Copy root index.html
    if os.path.exists(TEMP_INDEX_FILE):
        shutil.copy2(TEMP_INDEX_FILE, INDEX_FILE)
        logging.info(f"Copied main index.html to {INDEX_FILE}")

    # 5. Generate indices for subdirectories
    generate_directory_index(
        OUTPUT_SERVICES_DIR,
        os.path.join(OUTPUT_SERVICES_DIR, "index.html"),
        title="Azure Services IP Ranges",
        description="Clean, deduplicated and sorted IP ranges grouped by Azure Service. Available in combined (.txt), IPv4 (.ipv4.txt) and IPv6 (.ipv6.txt).",
        badge_label="Services"
    )

    generate_directory_index(
        OUTPUT_REGIONS_DIR,
        os.path.join(OUTPUT_REGIONS_DIR, "index.html"),
        title="Azure Regions IP Ranges",
        description="Complete IP ranges aggregated per Azure Region (e.g. brazilsouth, eastus, westeurope). Formatted for URL Table Aliases and dynamic lists.",
        badge_label="Regions"
    )

    generate_directory_index(
        JSON_DIR,
        os.path.join(JSON_DIR, "index.html"),
        title="Azure Service Tags JSON Archive",
        description="Historical weekly JSON dumps of Microsoft Azure Service Tags (12-week rolling window, Gzip compressed). Direct uncompressed access available via ServiceTags_Public.json.",
        badge_label="Archives"
    )

    logging.info("All outputs successfully finalized into docs/")

def cleanup_temp() -> None:
    """Clean up the temporary directory."""
    if os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR)
        logging.info("Temporary directory docs_temp cleaned up.")

def main() -> None:
    """Main execution entrypoint."""
    try:
        logging.info("Starting Azure Service Tags update process.")
        ensure_directories()

        json_url = fetch_latest_json_url()
        json_filename, json_path = download_json(json_url)

        meta = process_json(json_path)

        update_index_page(
            version=meta["version"],
            version_date=meta["version_date"],
            json_filename=json_filename,
            change_number=meta["change_number"],
            total_services=meta["total_services"],
            total_regions=meta["total_regions"]
        )

        finalize_output(json_path, json_filename)

        if not os.path.exists(DOCS_DIR) or not os.listdir(DOCS_DIR):
            raise RuntimeError("docs/ directory is unexpectedly empty after processing.")

        logging.info("Processing completed successfully!")

    except Exception as e:
        logging.error(f"Error during execution: {e}", exc_info=True)
        raise
    finally:
        cleanup_temp()

if __name__ == "__main__":
    main()
