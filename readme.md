# Cloud IP Ranges & Service Tags Automation Hub

> **Live Hub & Direct Downloads:** [https://leoescarpellin.github.io/cloudIPrange/](https://leoescarpellin.github.io/cloudIPrange/)  
> **Official Cloud Sources:** [Microsoft Azure](https://www.microsoft.com/en-us/download/details.aspx?id=56519) · [Amazon Web Services](https://ip-ranges.amazonaws.com/ip-ranges.json) · [Google Cloud (GCP)](https://www.gstatic.com/ipranges/cloud.json) · [Cloudflare](https://api.cloudflare.com/client/v4/ips)  
> **SquidGuard Contingency Mirror:** [UT1 Capitole Blacklists](https://leoescarpellin.github.io/cloudIPrange/squidguard/index.html) · [Direct Archive](https://leoescarpellin.github.io/cloudIPrange/squidguard/blacklists.tar.gz)

An automated utility for downloading, deduplicating, CIDR-collapsing, sorting, and publishing service and regional IP ranges for **Microsoft Azure**, **Amazon AWS**, **Google Cloud (GCP)**, and **Cloudflare** into clean plain-text CIDR lists.

Additionally, this project hosts an automated, high-availability **Contingency Mirror** for **SquidGuard Web Filter Blacklists** (the official successor to Shallalist, curated by Université Toulouse 1 Capitole), ensuring uninterrupted access for pfSense and Squid web filters.

Designed for direct integration with firewall aliases and dynamic network lists:
* **pfSense** (`URL Table (IPs)` Aliases / pfBlockerNG `Alias Native`)
* **OPNsense** (`URL Table (IPs)` Aliases)
* **Palo Alto Networks** (`External Dynamic Lists - EDL`)
* **MikroTik RouterOS** (`Address Lists`)
* **Fortinet FortiGate** (`External Threat Feeds`)
* **Cisco ASA / Firepower** (`Dynamic Objects / Security Intelligence`)

---

## Supported Cloud Providers

| Provider | Services | Regions | Direct URLs |
| :--- | :---: | :---: | :--- |
| 🟦 **Microsoft Azure** | 100 | 78 | [`ranges-services/`](https://leoescarpellin.github.io/cloudIPrange/ranges-services/) · [`ranges-regions/`](https://leoescarpellin.github.io/cloudIPrange/ranges-regions/) · [JSON](https://leoescarpellin.github.io/cloudIPrange/json-history/ServiceTags_Public.json) |
| 🟧 **Amazon AWS** | 27 | 43 | [`aws/ranges-services/`](https://leoescarpellin.github.io/cloudIPrange/aws/ranges-services/) · [`aws/ranges-regions/`](https://leoescarpellin.github.io/cloudIPrange/aws/ranges-regions/) · [JSON](https://leoescarpellin.github.io/cloudIPrange/aws/json-history/ip-ranges.json) |
| 🟥 **Google Cloud (GCP)** | Global List | 48 | [`gcp/ranges-regions/`](https://leoescarpellin.github.io/cloudIPrange/gcp/ranges-regions/) · [All GCP IPv4](https://leoescarpellin.github.io/cloudIPrange/gcp/ranges-regions/GoogleCloud.ipv4.txt) · [JSON](https://leoescarpellin.github.io/cloudIPrange/gcp/json-history/cloud.json) |
| 🟨 **Cloudflare** | Edge CDN / WAF | Global | [`cloudflare/`](https://leoescarpellin.github.io/cloudIPrange/cloudflare/) · [IPv4 List](https://leoescarpellin.github.io/cloudIPrange/cloudflare/cloudflare.ipv4.txt) · [IPv6 List](https://leoescarpellin.github.io/cloudIPrange/cloudflare/cloudflare.ipv6.txt) |

---

## Key Features

* **Strict Deduplication & CIDR Collapsing:** Automatically eliminates duplicate prefixes and collapses nested child subnets (e.g., a `/26` enclosed within a `/16` is automatically absorbed into the `/16`), merging contiguous blocks to minimize firewall table memory and lookup overhead.
* **Canonical CIDR Sorting:** Prefixes are sorted numerically by base address integer and subnet mask length.
* **Protocol Separation:** Every service and region is published in three formats:
  * `<name>.ipv4.txt` — IPv4 only (prevents family mismatch in pfSense / OPNsense rules)
  * `<name>.ipv6.txt` — IPv6 only
  * `<name>.txt` — Combined (IPv4 followed by IPv6)
* **Static JSON Mirrors:** Provides permanent uncompressed links to the latest raw JSON dumps from each provider.
* **Storage Optimization:** Historical weekly JSON files are maintained within a rolling 12-week retention window and compressed with Gzip (`.json.gz`), keeping the Git repository lightweight (<15 MB total).
* **Automated Weekly Updates:** Powered by GitHub Actions running every Wednesday at 11:00 UTC.

---

## Directory & URL Structure

```text
cloudIPrange/
├── docs/
│   ├── ranges-services/             # Azure services (legacy root mirror)
│   ├── ranges-regions/              # Azure regions (legacy root mirror)
│   ├── json-history/                # Azure JSON dumps (12-week archive)
│   │
│   ├── azure/                       # Microsoft Azure namespace
│   │   ├── ranges-services/         # 100 Azure services
│   │   └── ranges-regions/          # 78 Azure regions
│   │
│   ├── aws/                         # Amazon AWS namespace
│   │   ├── ranges-services/         # 27 AWS services (S3, EC2, CloudFront, etc.)
│   │   └── ranges-regions/          # 43 AWS regions (sa-east-1, us-east-1, etc.)
│   │
│   ├── gcp/                         # Google Cloud Platform namespace
│   │   └── ranges-regions/          # 48 GCP regions + GoogleCloud combined
│   │
│   ├── cloudflare/                  # Cloudflare Edge CDN & Proxy
│   │   ├── cloudflare.ipv4.txt      # 15 clean IPv4 CIDRs
│   │   ├── cloudflare.ipv6.txt      # 7 clean IPv6 CIDRs
│   │   └── cloudflare.txt           # Combined
│   │
│   └── squidguard/                  # SquidGuard Blacklist Contingency Mirror (UT1 Capitole)
│       ├── blacklists.tar.gz        # Complete archive (~25.4 MB, 80 categories)
│       ├── blacklists.tar.gz.sha256 # Cryptographic checksum
│       ├── index.html               # Dedicated mirror guide and category viewer
│       └── meta.json                # Mirror metadata and category list
```

---

## SquidGuard Web Filter Blacklists (Shallalist Successor Mirror)

> **Official Curation & Maintenance:** [Université Toulouse 1 Capitole (DSI)](https://dsi.ut-capitole.fr/blacklists/)  
> **Direct Ingestion URL for pfSense:** `https://leoescarpellin.github.io/cloudIPrange/squidguard/blacklists.tar.gz`  
> **Integrity Checksum (SHA-256):** [blacklists.tar.gz.sha256](https://leoescarpellin.github.io/cloudIPrange/squidguard/blacklists.tar.gz.sha256)  
> **Dedicated Guide & Category Explorer:** [SquidGuard Mirror Hub](https://leoescarpellin.github.io/cloudIPrange/squidguard/index.html)

### Why this Mirror Exists
Following the shutdown and abandonment of **Shallalist**, the **Université Toulouse 1 Capitole (França)** became the recognized reference authority maintaining public categorized domain and URL blacklists for Squid, SquidGuard, and pfSense.

To protect network administrators against single-point-of-failure risks and sudden project abandonment (as occurred with Shallalist), this repository hosts an automated, high-availability **Shallalist Successor Mirror**. It continuously synchronizes the archive, calculates cryptographic SHA-256 hashes, and serves the latest release via GitHub Pages CDN. All academic credits and curation belong to Université Toulouse 1 Capitole.

### pfSense SquidGuard Step-by-Step Configuration
1. In pfSense WebGUI, go to **Services &rarr; SquidGuard Proxy Filter**.
2. On **General Settings**, ensure **Enable** is checked.
3. Navigate to the **Blacklist** tab:
   * Check **Blacklist** (Enable blacklist).
   * In **Blacklist URL**, paste:
     ```text
     https://leoescarpellin.github.io/cloudIPrange/squidguard/blacklists.tar.gz
     ```
4. Click **Save**.
5. Switch to the **Blacklist update** tab and click **Download**. pfSense will fetch the archive, unpack categories into `/var/db/squidGuard/`, and compile the Berkeley DB (`.db`) tables.
6. Under **Common ACL** (or **Group ACL**), expand **Target Rules List** and define desired policies (`deny` or `allow`) for each category (e.g., `adult`, `malware`, `phishing`, `cryptojacking`, `social_networks`).
7. Click **Save**, then return to **General Settings** and click **Apply** to reload the SquidGuard filter daemon.

---

## Firewall Integration Guides

### 1. pfSense (URL Table Aliases / pfBlockerNG)

#### Via Native URL Table Alias:
1. Open pfSense WebGUI and go to **Firewall &rarr; Aliases &rarr; IP**.
2. Click **Add**.
3. Configure the alias:
   * **Name:** `Azure_Storage_IPv4` or `AWS_SaoPaulo_IPv4`
   * **Type:** `URL Table (IPs)`
   * **URL Examples:**
     * Azure: `https://leoescarpellin.github.io/cloudIPrange/ranges-services/AzureStorage.ipv4.txt`
     * AWS: `https://leoescarpellin.github.io/cloudIPrange/aws/ranges-regions/sa-east-1.ipv4.txt`
     * GCP: `https://leoescarpellin.github.io/cloudIPrange/gcp/ranges-regions/southamerica-east1.ipv4.txt`
     * Cloudflare: `https://leoescarpellin.github.io/cloudIPrange/cloudflare/cloudflare.ipv4.txt`
   * **Update Frequency:** `1` day (or `7` days)
4. Click **Save** and **Apply Changes**.
5. Use the alias as **Source** or **Destination** in your Firewall Rules.

#### Via pfBlockerNG (Best Practice):
* Go to **Firewall &rarr; pfBlockerNG &rarr; IP &rarr; IPv4**.
* Set **Action:** `Alias Native` (creates `pfB_<Name>` without adding rigid automatic rules).
* Add feed with format `Auto`.
* In **Firewall &rarr; Rules**, create a `Pass` rule at the top of the interface referencing `pfB_<Name>`.

---

### 2. OPNsense (URL Table Aliases)

1. Open OPNsense and go to **Firewall &rarr; Aliases**.
2. Click **+ (Add)**.
3. Configure:
   * **Name:** `AWS_SAEast_v4`
   * **Type:** `URL Table (IPs)`
   * **Content:** `https://leoescarpellin.github.io/cloudIPrange/aws/ranges-regions/sa-east-1.ipv4.txt`
   * **Refresh Frequency:** `1` day
4. Save and Apply Changes.

---

### 3. Palo Alto Networks (External Dynamic Lists - EDL)

1. Go to **Objects &rarr; External Dynamic Lists** and click **Add**.
2. Set **Type** to `IP List`.
3. In **Source URL**, enter the desired `.ipv4.txt` or `.txt` URL (e.g. `https://leoescarpellin.github.io/cloudIPrange/aws/ranges-services/S3.ipv4.txt`).
4. Set Repeat to `Daily` or `Weekly`.
5. Commit and reference the EDL object in your Security Policies.

---

### 4. MikroTik RouterOS (Address Lists)

```routeros
/tool fetch url="https://leoescarpellin.github.io/cloudIPrange/cloudflare/cloudflare.ipv4.txt" dst-path="cf_ips.txt"
:local content [/file get cf_ips.txt contents]
:local lineEnd 0
:local line ""
/ip firewall address-list remove [find list="Cloudflare_Edge"]
:while ([:len $content] > 0) do={
  :set lineEnd [:find $content "\n"]
  :if ($lineEnd = -1) do={:set lineEnd [:len $content]}
  :set line [:pick $content 0 $lineEnd]
  :set content [:pick $content ($lineEnd + 1) [:len $content]]
  :if ([:len $line] > 0) do={
    /ip firewall address-list add list="Cloudflare_Edge" address=$line comment="Cloudflare CDN/Proxy"
  }
}
```

---

### 5. Fortinet FortiGate (External Threat Feeds)

1. Go to **Security Fabric &rarr; Fabric Connectors &rarr; Create New**.
2. Select **Threat Feeds &rarr; IP Address**.
3. Configure:
   * **Name:** `AWS_S3_Feed`
   * **URL:** `https://leoescarpellin.github.io/cloudIPrange/aws/ranges-services/S3.ipv4.txt`
   * **Refresh Rate:** `Daily`
4. Use the connector in firewall policy destination matching.

---

### 6. Cisco Firepower (FMC) / ASA

1. In Firepower Management Center (FMC), navigate to **Objects &rarr; Object Management &rarr; Security Intelligence &rarr; Network Lists and Feeds**.
2. Add a new **Feed** with the desired URL.
3. Deploy configuration to managed FTD devices.

---

## Local Development

1. Clone repository:
   ```bash
   git clone https://github.com/leoescarpellin/cloudIPrange.git
   cd cloudIPrange
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the multi-cloud updater:
   ```bash
   python update_service_tags.py
   ```

---

## Acknowledgments

* Special thanks to [Enzo Gautier](https://github.com/enzo-g) and the original [enzo-g/azureIPranges](https://github.com/enzo-g/azureIPranges) repository, which served as the foundation and initial inspiration for this project.
* Special thanks to **Université Toulouse 1 Capitole (DSI)** for their outstanding, continuous work in curating and maintaining the open SquidGuard web filtering blacklists database.

---

## Disclaimer

This repository and its contents are provided "AS IS" without warranty of any kind. Microsoft, Amazon, Google, and Cloudflare periodically update their IP ranges. Verify ranges against your network requirements prior to production deployment.

---

## License

This project is open-source under the [MIT License](LICENSE).
