"""
VCDB (VERIS Community Database) Breach Incident Parser
=======================================================
Parses individual JSON incident files from the VCDB dataset into
clean, analysis-ready tables for SQL querying and Power BI visualisation.

Output tables:
  1. incidents        - Core incident metadata (one row per incident)
  2. actions          - Attack action types per incident (hacking, malware, etc.)
  3. actors           - Threat actors per incident (external, internal, partner)
  4. data_compromised - Types of data compromised per incident
  5. assets           - Asset varieties affected per incident
  6. discovery        - Discovery method per incident

Usage (Jupyter):
    from vcdb_parser import process_directory, write_csv_outputs, write_sqlite_output

    INPUT_DIR  = r"C:\\Users\\Maphu\\Downloads\\VCDB-master\\VCDB-master\\data\\json\\validated"
    OUTPUT_DIR = r"C:\\Users\\Maphu\\Downloads\\VCDB-master\\output"

    tables = process_directory(INPUT_DIR)
    write_csv_outputs(tables, OUTPUT_DIR)
    write_sqlite_output(tables, OUTPUT_DIR)
"""

import json
import os
import csv
import sqlite3
import argparse
from pathlib import Path

# ---------------------------------------------------------------------------
# NAICS industry code lookup (top-level 2-digit codes)
# ---------------------------------------------------------------------------
NAICS_LOOKUP = {
    "11": "Agriculture, Forestry, Fishing",
    "21": "Mining, Quarrying, Oil & Gas",
    "22": "Utilities",
    "23": "Construction",
    "31": "Manufacturing",
    "32": "Manufacturing",
    "33": "Manufacturing",
    "42": "Wholesale Trade",
    "44": "Retail Trade",
    "45": "Retail Trade",
    "48": "Transportation & Warehousing",
    "49": "Transportation & Warehousing",
    "51": "Information",
    "52": "Finance & Insurance",
    "53": "Real Estate",
    "54": "Professional & Technical Services",
    "55": "Management of Companies",
    "56": "Administrative & Support Services",
    "61": "Educational Services",
    "62": "Healthcare & Social Assistance",
    "71": "Arts, Entertainment & Recreation",
    "72": "Accommodation & Food Services",
    "81": "Other Services",
    "92": "Public Administration",
}

def naics_to_industry(code: str) -> str:
    """Map a NAICS code string to a readable industry name."""
    if not code or code == "Unknown":
        return "Unknown"
    code = str(code).strip()
    # Try 2-digit prefix first
    for length in [2, 3]:
        prefix = code[:length]
        if prefix in NAICS_LOOKUP:
            return NAICS_LOOKUP[prefix]
    return f"Other ({code})"


# ---------------------------------------------------------------------------
# Helper extractors
# ---------------------------------------------------------------------------

def safe_get(d: dict, *keys, default=None):
    """Safely navigate nested dict keys."""
    for key in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(key, default)
        if d is None:
            return default
    return d


def list_to_str(val, default="Unknown") -> str:
    """Convert a list to a pipe-separated string."""
    if isinstance(val, list):
        cleaned = [str(v) for v in val if v and str(v).strip()]
        return " | ".join(cleaned) if cleaned else default
    if val:
        return str(val)
    return default


def extract_incident(data: dict) -> dict:
    """Extract core incident fields into a flat dict."""
    incident_id = data.get("incident_id") or safe_get(data, "plus", "master_id", default="Unknown")

    # Timeline
    year  = safe_get(data, "timeline", "incident", "year")
    month = safe_get(data, "timeline", "incident", "month")
    day   = safe_get(data, "timeline", "incident", "day")

    # Discovery time (dwell time)
    disc_unit  = safe_get(data, "timeline", "discovery", "unit")
    disc_value = safe_get(data, "timeline", "discovery", "value")

    # Victim
    victim          = data.get("victim", {})
    country         = list_to_str(victim.get("country"), "Unknown")
    industry_code   = str(victim.get("industry", "Unknown"))
    industry_name   = naics_to_industry(industry_code)
    employee_count  = victim.get("employee_count", "Unknown")
    victim_id       = victim.get("victim_id", "Unknown")
    government      = list_to_str(victim.get("government"), "NA")

    # Confidentiality
    conf            = safe_get(data, "attribute", "confidentiality", default={})
    data_disclosure = conf.get("data_disclosure", "Unknown")
    data_total      = conf.get("data_total")
    data_state      = list_to_str(conf.get("state"), "Unknown")

    # Security incident confirmation
    security_incident = data.get("security_incident", "Unknown")
    confidence        = data.get("confidence", "Unknown")

    # Action types present (boolean flags)
    actions = data.get("action", {})
    has_hacking  = "hacking"  in actions
    has_malware  = "malware"  in actions
    has_social   = "social"   in actions
    has_physical = "physical" in actions
    has_misuse   = "misuse"   in actions
    has_error    = "error"    in actions
    has_unknown  = "unknown"  in actions

    # Actor types present
    actors = data.get("actor", {})
    has_external = "external" in actors
    has_internal = "internal" in actors
    has_partner  = "partner"  in actors

    # Discovery method top-level
    disc_methods = data.get("discovery_method", {})
    if "external" in disc_methods:
        discovery_source = "External"
    elif "internal" in disc_methods:
        discovery_source = "Internal"
    elif "unknown" in disc_methods:
        discovery_source = "Unknown"
    else:
        discovery_source = "Unknown"

    # Summary
    summary = data.get("summary", "")[:500] if data.get("summary") else ""

    return {
        "incident_id":        incident_id,
        "year":               year,
        "month":              month,
        "day":                day,
        "victim_id":          victim_id,
        "country":            country,
        "industry_code":      industry_code,
        "industry_name":      industry_name,
        "employee_count":     employee_count,
        "government":         government,
        "security_incident":  security_incident,
        "confidence":         confidence,
        "data_disclosure":    data_disclosure,
        "data_total_records": data_total,
        "data_state":         data_state,
        "discovery_source":   discovery_source,
        "discovery_unit":     disc_unit,
        "discovery_value":    disc_value,
        "has_hacking":        int(has_hacking),
        "has_malware":        int(has_malware),
        "has_social":         int(has_social),
        "has_physical":       int(has_physical),
        "has_misuse":         int(has_misuse),
        "has_error":          int(has_error),
        "has_unknown_action": int(has_unknown),
        "has_external_actor": int(has_external),
        "has_internal_actor": int(has_internal),
        "has_partner_actor":  int(has_partner),
        "summary":            summary,
    }


def extract_actions(data: dict, incident_id: str) -> list:
    """Extract one row per action type with its varieties and vectors."""
    records = []
    actions = data.get("action", {})
    for action_type, details in actions.items():
        if not isinstance(details, dict):
            continue
        varieties = list_to_str(details.get("variety"), "Unknown")
        vectors   = list_to_str(details.get("vector"), "Unknown")
        result    = list_to_str(details.get("result"), "Unknown")
        records.append({
            "incident_id":   incident_id,
            "action_type":   action_type,
            "variety":       varieties,
            "vector":        vectors,
            "result":        result,
        })
    return records


def extract_actors(data: dict, incident_id: str) -> list:
    """Extract one row per actor type with motive, variety, country."""
    records = []
    actors = data.get("actor", {})
    for actor_type, details in actors.items():
        if not isinstance(details, dict):
            continue
        motive  = list_to_str(details.get("motive"), "Unknown")
        variety = list_to_str(details.get("variety"), "Unknown")
        country = list_to_str(details.get("country"), "Unknown")
        records.append({
            "incident_id": incident_id,
            "actor_type":  actor_type,
            "variety":     variety,
            "motive":      motive,
            "country":     country,
        })
    return records


def extract_data_compromised(data: dict, incident_id: str) -> list:
    """Extract one row per data type compromised."""
    records = []
    conf = safe_get(data, "attribute", "confidentiality", default={})
    data_items = conf.get("data", [])
    if not isinstance(data_items, list):
        return records
    data_victims = list_to_str(conf.get("data_victim"), "Unknown")
    for item in data_items:
        if not isinstance(item, dict):
            continue
        records.append({
            "incident_id":  incident_id,
            "data_variety": item.get("variety", "Unknown"),
            "amount":       item.get("amount"),
            "data_victim":  data_victims,
        })
    return records


def extract_assets(data: dict, incident_id: str) -> list:
    """Extract one row per asset variety affected."""
    records = []
    asset_list = safe_get(data, "asset", "assets", default=[])
    if not isinstance(asset_list, list):
        return records
    cloud = list_to_str(safe_get(data, "asset", "cloud"), "Unknown")
    for item in asset_list:
        if not isinstance(item, dict):
            continue
        variety = item.get("variety", "Unknown")
        # Parse asset category from variety string e.g. "S - Database" -> "Server"
        category_map = {
            "S": "Server", "U": "User Device", "N": "Network",
            "M": "Media", "P": "Person", "T": "Kiosk/Terminal"
        }
        prefix = variety.split(" - ")[0].strip() if " - " in variety else "Unknown"
        category = category_map.get(prefix, "Unknown")
        records.append({
            "incident_id":     incident_id,
            "asset_variety":   variety,
            "asset_category":  category,
            "cloud":           cloud,
            "amount":          item.get("amount"),
        })
    return records


def extract_discovery(data: dict, incident_id: str) -> list:
    """Extract discovery method details."""
    records = []
    disc = data.get("discovery_method", {})
    for source, details in disc.items():
        if source == "unknown" or not isinstance(details, dict):
            variety = "Unknown"
        else:
            variety = list_to_str(details.get("variety"), "Unknown")
        records.append({
            "incident_id":      incident_id,
            "discovery_source": source,
            "discovery_variety": variety,
        })
    return records


# ---------------------------------------------------------------------------
# File and directory processors
# ---------------------------------------------------------------------------

def process_file(filepath: str) -> dict:
    """Parse a single VCDB JSON file. Returns dict of table -> [records]."""
    with open(filepath, "r", encoding="utf-8-sig") as f:
        data = json.load(f)

    incident_id = data.get("incident_id") or safe_get(
        data, "plus", "master_id", default=str(filepath)
    )

    # Validate this is a genuine VCDB incident record
    if not data.get("schema_version") and not data.get("security_incident"):
        return None
    if not data.get("timeline", {}).get("incident", {}).get("year"):
        return None

    return {
        "incidents":        [extract_incident(data)],
        "actions":          extract_actions(data, incident_id),
        "actors":           extract_actors(data, incident_id),
        "data_compromised": extract_data_compromised(data, incident_id),
        "assets":           extract_assets(data, incident_id),
        "discovery":        extract_discovery(data, incident_id),
    }


def process_directory(input_dir: str) -> dict:
    """Process all .json/.JSON files in a directory."""
    all_tables = {
        "incidents":        [],
        "actions":          [],
        "actors":           [],
        "data_compromised": [],
        "assets":           [],
        "discovery":        [],
    }

    files = sorted(
        [f for f in Path(input_dir).glob("**/*")
         if f.suffix.lower() == ".json"]
    )

    if not files:
        print(f"  No JSON files found in {input_dir}")
        return all_tables

    errors = 0
    for fp in files:
        try:
            result = process_file(str(fp))
            if result is None:
                continue
            for table, records in result.items():
                all_tables[table].extend(records)
        except Exception as e:
            errors += 1
            if errors <= 5:
                print(f"  [WARN] Skipped {fp.name}: {e}")

    print(f"  Processed {len(files)} files ({errors} skipped)")
    return all_tables


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

def write_csv_outputs(tables: dict, output_dir: str):
    """Write each table to a separate CSV file."""
    os.makedirs(output_dir, exist_ok=True)
    for table_name, records in tables.items():
        if not records:
            print(f"  [SKIP] {table_name} — no records")
            continue
        out_path = os.path.join(output_dir, f"{table_name}.csv")
        fieldnames = list(records[0].keys())
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(records)
        print(f"  [OK]   {table_name}.csv  ({len(records)} rows)")


def write_sqlite_output(tables: dict, output_dir: str) -> str:
    """Write all tables into a single SQLite database."""
    os.makedirs(output_dir, exist_ok=True)
    db_path = os.path.join(output_dir, "vcdb_breaches.db")
    conn = sqlite3.connect(db_path)

    TEXT_COLS = {
        "incident_id", "victim_id", "country", "industry_code",
        "industry_name", "employee_count", "government",
        "security_incident", "confidence", "data_disclosure",
        "data_state", "discovery_source", "discovery_unit",
        "summary", "action_type", "variety", "vector", "result",
        "actor_type", "motive", "data_variety", "data_victim",
        "asset_variety", "asset_category", "cloud",
        "discovery_variety", "government",
    }

    for table_name, records in tables.items():
        if not records:
            continue
        cols = list(records[0].keys())
        col_defs = []
        for col in cols:
            if col in TEXT_COLS or isinstance(records[0].get(col), str):
                col_defs.append(f'"{col}" TEXT')
            else:
                col_defs.append(f'"{col}" REAL')

        conn.execute(f"DROP TABLE IF EXISTS {table_name}")
        conn.execute(f"CREATE TABLE {table_name} ({', '.join(col_defs)})")
        placeholders = ", ".join(["?"] * len(cols))
        for rec in records:
            values = [rec.get(c) for c in cols]
            conn.execute(
                f"INSERT INTO {table_name} VALUES ({placeholders})", values
            )
        conn.commit()
        print(f"  [OK]   {table_name}  ({len(records)} rows)")

    conn.close()
    print(f"\n  Database saved to: {db_path}")
    return db_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Parse VCDB JSON breach incident files into analysis-ready tables."
    )
    parser.add_argument("--input",  "-i", required=True)
    parser.add_argument("--output", "-o", default="./output")
    parser.add_argument("--format", "-f", choices=["csv", "sqlite", "both"],
                        default="both")
    args = parser.parse_args()

    print(f"\nVCDB Parser")
    print(f"  Input  : {args.input}")
    print(f"  Output : {args.output}")
    print(f"  Format : {args.format}\n")

    print("Processing files...")
    tables = process_directory(args.input)
    total = sum(len(r) for r in tables.values())
    print(f"\nTotal records extracted: {total}\n")

    if args.format in ("csv", "both"):
        print("Writing CSV files...")
        write_csv_outputs(tables, args.output)
        print()
    if args.format in ("sqlite", "both"):
        print("Writing SQLite database...")
        write_sqlite_output(tables, args.output)

    print("\nDone.")


if __name__ == "__main__":
    main()
