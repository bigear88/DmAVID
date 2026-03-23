#!/usr/bin/env python3
"""
DavidAgent Vulnerability Intelligence Collector: Aggregates real-world DeFi exploit
data from multiple open-source intelligence feeds and updates the RAG knowledge base.

Sources:
    1. DeFiHackLabs (SunWeb3Sec/DeFiHackLabs) - Foundry PoC reproductions
    2. Rekt News (rekt.news/rss/) - Incident report RSS feed
    3. SlowMist Hacked DB - Structured attack event database
    4. Code4rena - Public audit report findings

The collector normalises each event into a unified JSON schema, persists raw intel
to data/vuln_intel/, and optionally refreshes the ChromaDB RAG knowledge base via
build_knowledge_base.py.

Importable entry-points used by 14_adversarial_loop.py:
    collect_intel(sources, dry_run) -> List[dict]
    update_knowledge_base(events, dry_run) -> int
"""

import argparse
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from openai import OpenAI

# ── Logging ────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────
BASE_DIR = os.environ.get(
    "DAVID_BASE_DIR", "/home/curtis/defi-llm-vulnerability-detection"
)
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")
INTEL_DIR = os.path.join(BASE_DIR, "data", "vuln_intel")
DEFIHACKLABS_DIR = os.path.join(BASE_DIR, "data", "defihacklabs")

MODEL = "gpt-4.1-mini"

DEFIHACKLABS_REPO = "https://github.com/SunWeb3Sec/DeFiHackLabs.git"
REKT_RSS_URL = "https://rekt.news/rss/"
SLOWMIST_API_URL = "https://hacked.slowmist.io/api/hacked/list"
CODE4RENA_API_URL = "https://raw.githubusercontent.com/code-423n4/code423n4.com/main/_data/findings/findings.json"

ALL_SOURCES = ["defihacklabs", "rekt", "slowmist", "code4rena"]

# Rate-limiting defaults (seconds between HTTP requests per source)
RATE_LIMIT_SECONDS = 1.5

# Initialise OpenAI client (uses OPENAI_API_KEY env var)
client = OpenAI()


# ── Helpers ────────────────────────────────────────────────────────

def _ensure_dir(path: str) -> None:
    """Create directory (and parents) if it does not exist."""
    Path(path).mkdir(parents=True, exist_ok=True)


def _event_id(source: str, protocol: str, date: str) -> str:
    """Deterministic event ID based on source + protocol + date."""
    raw = f"{source}:{protocol}:{date}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _rate_limit() -> None:
    """Simple sleep-based rate limiter."""
    time.sleep(RATE_LIMIT_SECONDS)


def _safe_get(url: str, timeout: int = 30, **kwargs) -> Optional[requests.Response]:
    """HTTP GET with error handling and rate limiting."""
    try:
        _rate_limit()
        resp = requests.get(url, timeout=timeout, **kwargs)
        resp.raise_for_status()
        return resp
    except requests.RequestException as exc:
        logger.error("HTTP GET failed for %s: %s", url, exc)
        return None


def _extract_attack_info_llm(text: str) -> Dict[str, Any]:
    """Use gpt-4.1-mini to extract structured vulnerability info from free-text."""
    prompt = (
        "You are a DeFi security analyst. Extract structured vulnerability "
        "information from the following incident report text.\n\n"
        f"TEXT:\n{text[:4000]}\n\n"
        "Return ONLY a JSON object (no markdown) with these fields:\n"
        '{\n'
        '  "protocol": "protocol name",\n'
        '  "chain": "blockchain name or Unknown",\n'
        '  "loss_usd": estimated loss as number or 0,\n'
        '  "vuln_type": "vulnerability category (e.g. reentrancy, flash_loan, access_control, price_manipulation, logic_error, rug_pull, other)",\n'
        '  "attack_vector": "brief attack mechanism",\n'
        '  "description": "concise summary (1-2 sentences)"\n'
        "}\n"
    )
    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,
            max_tokens=512,
        )
        content = response.choices[0].message.content.strip()
        # Strip markdown fences if present
        if content.startswith("```"):
            content = re.sub(r"^```(?:json)?\s*", "", content)
            content = re.sub(r"\s*```$", "", content)
        return json.loads(content)
    except Exception as exc:
        logger.warning("LLM extraction failed: %s", exc)
        return {}


# ── Source: DeFiHackLabs ───────────────────────────────────────────

def _clone_or_pull_defihacklabs() -> str:
    """Clone or update the DeFiHackLabs repository."""
    _ensure_dir(os.path.dirname(DEFIHACKLABS_DIR))
    if os.path.isdir(os.path.join(DEFIHACKLABS_DIR, ".git")):
        logger.info("Pulling latest DeFiHackLabs commits …")
        try:
            subprocess.run(
                ["git", "-C", DEFIHACKLABS_DIR, "pull", "--ff-only"],
                capture_output=True, text=True, timeout=120,
            )
        except Exception as exc:
            logger.warning("git pull failed: %s", exc)
    else:
        logger.info("Cloning DeFiHackLabs repository …")
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", DEFIHACKLABS_REPO, DEFIHACKLABS_DIR],
                capture_output=True, text=True, timeout=300,
            )
        except Exception as exc:
            logger.error("git clone failed: %s", exc)
    return DEFIHACKLABS_DIR


def _parse_defihacklabs_file(filepath: str) -> Optional[Dict[str, Any]]:
    """Parse a single DeFiHackLabs Foundry test file for exploit metadata.

    File names typically look like:
        Reentrancy_exp.sol   or   ProtocolName_exp.sol
    and contain comments such as:
        // Exploit : Reentrancy
        // Date    : 2024-01-15
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read(8192)  # first 8 KB is usually enough
    except OSError:
        return None

    basename = os.path.basename(filepath)

    # Try to extract metadata from header comments
    protocol_match = re.search(
        r"(?:Protocol|Name|Target)\s*[:=]\s*(.+)", content, re.IGNORECASE
    )
    date_match = re.search(
        r"(?:Date|Time)\s*[:=]\s*(\d{4}[-/]\d{2}[-/]\d{2})", content, re.IGNORECASE
    )
    vuln_match = re.search(
        r"(?:Exploit|Vulnerability|Attack|Type)\s*[:=]\s*(.+)",
        content,
        re.IGNORECASE,
    )
    loss_match = re.search(
        r"(?:Loss|Amount|Stolen)\s*[:=~]\s*\$?\s*([\d,.]+)\s*(?:USD|M|K)?",
        content,
        re.IGNORECASE,
    )

    protocol = (
        protocol_match.group(1).strip()
        if protocol_match
        else basename.replace("_exp.sol", "").replace(".sol", "").replace("_", " ")
    )
    date_str = date_match.group(1).strip().replace("/", "-") if date_match else "unknown"
    vuln_type = vuln_match.group(1).strip().lower() if vuln_match else "unknown"
    loss_usd = 0.0
    if loss_match:
        raw_loss = loss_match.group(1).replace(",", "")
        try:
            loss_usd = float(raw_loss)
        except ValueError:
            pass

    event_id = _event_id("defihacklabs", protocol, date_str)
    return {
        "id": event_id,
        "date": date_str,
        "protocol": protocol,
        "chain": "Ethereum",
        "loss_usd": loss_usd,
        "vuln_type": vuln_type,
        "attack_vector": vuln_type,
        "description": f"DeFiHackLabs PoC reproduction for {protocol}",
        "poc_link": f"https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/{os.path.relpath(filepath, DEFIHACKLABS_DIR).replace(os.sep, '/')}",
        "source": "defihacklabs",
    }


def collect_defihacklabs(dry_run: bool = False) -> List[Dict[str, Any]]:
    """Collect vulnerability events from DeFiHackLabs repository."""
    logger.info("Collecting from DeFiHackLabs …")
    events: List[Dict[str, Any]] = []

    if dry_run:
        logger.info("[dry-run] Would clone/pull DeFiHackLabs and parse Foundry tests")
        return events

    repo_dir = _clone_or_pull_defihacklabs()
    test_dir = os.path.join(repo_dir, "src", "test")

    if not os.path.isdir(test_dir):
        logger.warning("DeFiHackLabs test directory not found: %s", test_dir)
        return events

    sol_files = list(Path(test_dir).rglob("*.sol"))
    logger.info("Found %d Foundry test files in DeFiHackLabs", len(sol_files))

    for sol_file in sol_files:
        event = _parse_defihacklabs_file(str(sol_file))
        if event:
            events.append(event)

    logger.info("Parsed %d events from DeFiHackLabs", len(events))
    return events


# ── Source: Rekt News ──────────────────────────────────────────────

def collect_rekt(dry_run: bool = False) -> List[Dict[str, Any]]:
    """Collect vulnerability events from Rekt News RSS feed."""
    logger.info("Collecting from Rekt News RSS …")
    events: List[Dict[str, Any]] = []

    if dry_run:
        logger.info("[dry-run] Would fetch and parse Rekt News RSS feed")
        return events

    resp = _safe_get(REKT_RSS_URL)
    if resp is None:
        return events

    try:
        root = ET.fromstring(resp.content)
    except ET.ParseError as exc:
        logger.error("Failed to parse Rekt RSS XML: %s", exc)
        return events

    # RSS 2.0 structure: <rss><channel><item>…</item></channel></rss>
    items = root.findall(".//item")
    logger.info("Rekt RSS returned %d items", len(items))

    for item in items:
        title = (item.findtext("title") or "").strip()
        description = (item.findtext("description") or "").strip()
        link = (item.findtext("link") or "").strip()
        pub_date = (item.findtext("pubDate") or "").strip()

        # Convert pub_date to ISO format
        date_str = "unknown"
        if pub_date:
            try:
                # RSS date format: "Mon, 02 Jan 2006 15:04:05 +0000"
                dt = datetime.strptime(pub_date[:25].strip(), "%a, %d %b %Y %H:%M:%S")
                date_str = dt.strftime("%Y-%m-%d")
            except ValueError:
                date_str = pub_date[:10]

        # Use LLM to extract structured info from description
        combined_text = f"Title: {title}\nDescription: {description}"
        extracted = _extract_attack_info_llm(combined_text)

        protocol = extracted.get("protocol", title.split(" ")[0] if title else "Unknown")
        event_id = _event_id("rekt", protocol, date_str)

        events.append({
            "id": event_id,
            "date": date_str,
            "protocol": protocol,
            "chain": extracted.get("chain", "Unknown"),
            "loss_usd": extracted.get("loss_usd", 0),
            "vuln_type": extracted.get("vuln_type", "unknown"),
            "attack_vector": extracted.get("attack_vector", "unknown"),
            "description": extracted.get(
                "description", f"Rekt News report: {title}"
            ),
            "poc_link": link,
            "source": "rekt",
        })

    logger.info("Parsed %d events from Rekt News", len(events))
    return events


# ── Source: SlowMist Hacked DB ─────────────────────────────────────

def collect_slowmist(dry_run: bool = False) -> List[Dict[str, Any]]:
    """Collect vulnerability events from SlowMist Hacked database."""
    logger.info("Collecting from SlowMist Hacked DB …")
    events: List[Dict[str, Any]] = []

    if dry_run:
        logger.info("[dry-run] Would fetch SlowMist Hacked DB entries")
        return events

    resp = _safe_get(SLOWMIST_API_URL)
    if resp is None:
        return events

    try:
        data = resp.json()
    except (ValueError, json.JSONDecodeError) as exc:
        logger.error("Failed to parse SlowMist JSON: %s", exc)
        return events

    records = data if isinstance(data, list) else data.get("data", data.get("list", []))
    logger.info("SlowMist returned %d records", len(records))

    for record in records:
        protocol = record.get("name", record.get("project", "Unknown"))
        date_str = record.get("time", record.get("date", "unknown"))
        if date_str and len(date_str) >= 10:
            date_str = date_str[:10]

        loss_raw = record.get("amount", record.get("loss", "0"))
        try:
            loss_usd = float(str(loss_raw).replace(",", "").replace("$", "").strip())
        except (ValueError, TypeError):
            loss_usd = 0.0

        vuln_type = record.get("type", record.get("attack_method", "unknown"))
        chain = record.get("chain", record.get("network", "Unknown"))
        description = record.get("description", record.get("detail", ""))
        link = record.get("link", record.get("url", ""))

        event_id = _event_id("slowmist", protocol, date_str)

        events.append({
            "id": event_id,
            "date": date_str,
            "protocol": protocol,
            "chain": chain if chain else "Unknown",
            "loss_usd": loss_usd,
            "vuln_type": vuln_type.lower() if vuln_type else "unknown",
            "attack_vector": vuln_type.lower() if vuln_type else "unknown",
            "description": description[:500] if description else f"SlowMist record: {protocol}",
            "poc_link": link,
            "source": "slowmist",
        })

    logger.info("Parsed %d events from SlowMist", len(events))
    return events


# ── Source: Code4rena ──────────────────────────────────────────────

def collect_code4rena(dry_run: bool = False) -> List[Dict[str, Any]]:
    """Collect vulnerability findings from Code4rena public reports."""
    logger.info("Collecting from Code4rena …")
    events: List[Dict[str, Any]] = []

    if dry_run:
        logger.info("[dry-run] Would fetch Code4rena public findings")
        return events

    resp = _safe_get(CODE4RENA_API_URL)
    if resp is None:
        return events

    try:
        data = resp.json()
    except (ValueError, json.JSONDecodeError) as exc:
        logger.error("Failed to parse Code4rena JSON: %s", exc)
        return events

    findings = data if isinstance(data, list) else data.get("findings", [])
    logger.info("Code4rena returned %d findings", len(findings))

    for finding in findings:
        title = finding.get("title", "")
        contest = finding.get("contest", finding.get("contestSlug", "unknown"))
        severity = finding.get("severity", finding.get("risk", "unknown"))
        body = finding.get("body", finding.get("details", ""))

        # Only collect high/medium severity
        if severity and severity.lower() not in ("high", "medium", "3 (high)", "2 (med)", "h", "m"):
            continue

        date_str = finding.get("date", finding.get("updatedAt", "unknown"))
        if date_str and len(date_str) >= 10:
            date_str = date_str[:10]

        # Determine vuln_type from title / body heuristics
        vuln_type = "unknown"
        title_lower = (title + " " + body[:200]).lower()
        if "reentrancy" in title_lower or "reentrant" in title_lower:
            vuln_type = "reentrancy"
        elif "overflow" in title_lower or "underflow" in title_lower:
            vuln_type = "integer_overflow"
        elif "access control" in title_lower or "unauthorized" in title_lower:
            vuln_type = "access_control"
        elif "flash loan" in title_lower or "flashloan" in title_lower:
            vuln_type = "flash_loan"
        elif "oracle" in title_lower or "price manipul" in title_lower:
            vuln_type = "price_manipulation"
        elif "logic" in title_lower:
            vuln_type = "logic_error"

        link = finding.get("url", finding.get("link", ""))
        event_id = _event_id("code4rena", contest, date_str)

        events.append({
            "id": event_id,
            "date": date_str,
            "protocol": contest,
            "chain": "Ethereum",
            "loss_usd": 0,
            "vuln_type": vuln_type,
            "attack_vector": vuln_type,
            "description": (title + ": " + body[:300]) if body else title,
            "poc_link": link,
            "source": "code4rena",
        })

    logger.info("Parsed %d events from Code4rena", len(events))
    return events


# ── Aggregation / Dedup ────────────────────────────────────────────

SOURCE_COLLECTORS = {
    "defihacklabs": collect_defihacklabs,
    "rekt": collect_rekt,
    "slowmist": collect_slowmist,
    "code4rena": collect_code4rena,
}


def collect_intel(
    sources: Optional[List[str]] = None,
    dry_run: bool = False,
) -> List[Dict[str, Any]]:
    """
    Collect vulnerability intelligence from the specified (or all) sources.

    Args:
        sources: List of source keys to collect from. None means all.
        dry_run: If True, preview operations without writing or fetching.

    Returns:
        Deduplicated list of structured vulnerability events.
    """
    if sources is None:
        sources = ALL_SOURCES

    all_events: List[Dict[str, Any]] = []
    for src in sources:
        collector = SOURCE_COLLECTORS.get(src)
        if collector is None:
            logger.warning("Unknown source: %s (valid: %s)", src, ALL_SOURCES)
            continue
        try:
            events = collector(dry_run=dry_run)
            all_events.extend(events)
            logger.info("Source %-15s  yielded %d events", src, len(events))
        except Exception as exc:
            logger.error("Collector %s failed: %s", src, exc)

    # Deduplicate by event id
    seen_ids: set = set()
    unique_events: List[Dict[str, Any]] = []
    for ev in all_events:
        eid = ev.get("id", "")
        if eid and eid not in seen_ids:
            seen_ids.add(eid)
            unique_events.append(ev)

    logger.info(
        "Collected %d total events (%d unique) from %d sources",
        len(all_events),
        len(unique_events),
        len(sources),
    )

    # Persist raw intel to disk
    if not dry_run and unique_events:
        _save_raw_intel(unique_events)

    return unique_events


def _save_raw_intel(events: List[Dict[str, Any]]) -> str:
    """Write collected events to a timestamped JSON file."""
    _ensure_dir(INTEL_DIR)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(INTEL_DIR, f"intel_{timestamp}.json")
    payload = {
        "collected_at": datetime.now().isoformat(),
        "count": len(events),
        "events": events,
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    logger.info("Raw intel saved to %s", out_path)
    return out_path


# ── Knowledge-base update ─────────────────────────────────────────

def _event_to_kb_entry(event: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a normalised event into a knowledge-base entry compatible with
    build_knowledge_base.py / ChromaDB ingestion."""
    return {
        "id": event["id"],
        "category": event.get("vuln_type", "unknown"),
        "title": f'{event.get("protocol", "Unknown")} - {event.get("vuln_type", "incident")}',
        "description": event.get("description", ""),
        "vulnerability_pattern": event.get("attack_vector", ""),
        "real_world_example": (
            f'{event.get("protocol", "Unknown")} ({event.get("date", "")}) '
            f'loss ~${event.get("loss_usd", 0):,.0f}'
        ),
        "mitigation": "",
        "severity": "high" if event.get("loss_usd", 0) > 100_000 else "medium",
        "source": event.get("source", ""),
        "poc_link": event.get("poc_link", ""),
        "chain": event.get("chain", "Unknown"),
        "date": event.get("date", "unknown"),
    }


def update_knowledge_base(
    events: List[Dict[str, Any]],
    dry_run: bool = False,
) -> int:
    """
    Update the RAG knowledge base with new vulnerability events.

    Converts events to ChromaDB-compatible entries and optionally calls
    build_knowledge_base.py to refresh embeddings.

    Args:
        events: List of structured vulnerability events.
        dry_run: If True, preview without writing.

    Returns:
        Number of new entries added.
    """
    if not events:
        logger.info("No events to add to knowledge base")
        return 0

    kb_entries = [_event_to_kb_entry(ev) for ev in events]

    if dry_run:
        logger.info(
            "[dry-run] Would add %d entries to knowledge base", len(kb_entries)
        )
        for entry in kb_entries[:5]:
            logger.info(
                "  -> %s | %s | %s",
                entry["category"],
                entry["title"],
                entry.get("real_world_example", ""),
            )
        if len(kb_entries) > 5:
            logger.info("  … and %d more", len(kb_entries) - 5)
        return 0

    # Load existing RAG knowledge base JSON (same format as 14_adversarial_loop.py)
    rag_kb_path = os.path.join(BASE_DIR, "data", "rag_knowledge_base.json")
    if os.path.exists(rag_kb_path):
        with open(rag_kb_path, "r", encoding="utf-8") as fh:
            rag_kb = json.load(fh)
    else:
        rag_kb = {"patterns": {}, "vulnerability_types": {}, "metadata": {}}

    added = 0
    for entry in kb_entries:
        eid = entry["id"]
        if eid not in rag_kb["patterns"]:
            rag_kb["patterns"][eid] = entry
            added += 1
            vtype = entry.get("category", "unknown")
            if vtype not in rag_kb["vulnerability_types"]:
                rag_kb["vulnerability_types"][vtype] = []
            rag_kb["vulnerability_types"][vtype].append(eid)

    rag_kb["metadata"]["last_updated"] = datetime.now().isoformat()
    rag_kb["metadata"]["total_patterns"] = len(rag_kb["patterns"])

    _ensure_dir(os.path.dirname(rag_kb_path))
    with open(rag_kb_path, "w", encoding="utf-8") as fh:
        json.dump(rag_kb, fh, indent=2, ensure_ascii=False)
    logger.info("RAG knowledge base updated: %d new entries (total %d)", added, len(rag_kb["patterns"]))

    # Also write entries to the knowledge/ directory for build_knowledge_base.py
    vuln_intel_kb_path = os.path.join(
        SCRIPTS_DIR, "knowledge", "vuln_intel_entries.json"
    )
    _ensure_dir(os.path.dirname(vuln_intel_kb_path))
    with open(vuln_intel_kb_path, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "metadata": {
                    "source": "vuln_intel_collector",
                    "generated_at": datetime.now().isoformat(),
                    "categories": list(
                        {e.get("category", "unknown") for e in kb_entries}
                    ),
                },
                "entries": kb_entries,
            },
            fh,
            indent=2,
            ensure_ascii=False,
        )
    logger.info("Knowledge entries written to %s", vuln_intel_kb_path)

    # Attempt to call build_knowledge_base.py to refresh ChromaDB embeddings
    build_kb_script = os.path.join(SCRIPTS_DIR, "build_knowledge_base.py")
    if os.path.isfile(build_kb_script):
        logger.info("Refreshing ChromaDB embeddings via build_knowledge_base.py …")
        try:
            result = subprocess.run(
                [sys.executable, build_kb_script],
                capture_output=True, text=True, timeout=300,
                cwd=SCRIPTS_DIR,
            )
            if result.returncode == 0:
                logger.info("ChromaDB embeddings refreshed successfully")
            else:
                logger.warning(
                    "build_knowledge_base.py exited with code %d: %s",
                    result.returncode,
                    result.stderr[:500],
                )
        except Exception as exc:
            logger.warning("Failed to run build_knowledge_base.py: %s", exc)
    else:
        logger.info("build_knowledge_base.py not found at %s — skipping embedding refresh", build_kb_script)

    return added


# ── CLI ────────────────────────────────────────────────────────────

def main() -> int:
    """CLI entry-point for the Vulnerability Intelligence Collector."""
    global BASE_DIR, SCRIPTS_DIR, INTEL_DIR, DEFIHACKLABS_DIR

    parser = argparse.ArgumentParser(
        description="DavidAgent Vulnerability Intelligence Collector — "
        "aggregates real-world DeFi exploit data and updates the RAG knowledge base.",
    )
    parser.add_argument(
        "--source",
        type=str,
        nargs="+",
        choices=ALL_SOURCES,
        default=None,
        help="Specific source(s) to collect from (default: all).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview operations without fetching data or writing files.",
    )
    parser.add_argument(
        "--skip-kb-update",
        action="store_true",
        help="Collect intel but do not update the RAG knowledge base.",
    )
    parser.add_argument(
        "--base-dir",
        type=str,
        default=None,
        help="Override base project directory.",
    )
    args = parser.parse_args()

    # Allow runtime override of BASE_DIR
    if args.base_dir is not None and args.base_dir != BASE_DIR:
        BASE_DIR = args.base_dir
        SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")
        INTEL_DIR = os.path.join(BASE_DIR, "data", "vuln_intel")
        DEFIHACKLABS_DIR = os.path.join(BASE_DIR, "data", "defihacklabs")

    logger.info("=" * 70)
    logger.info("DavidAgent Vulnerability Intelligence Collector")
    logger.info("=" * 70)
    logger.info("Base directory : %s", BASE_DIR)
    logger.info("Sources        : %s", args.source or "all")
    logger.info("Dry run        : %s", args.dry_run)

    # Step 1 — Collect intelligence
    events = collect_intel(sources=args.source, dry_run=args.dry_run)

    if not events:
        logger.info("No events collected — nothing to do.")
        return 0

    # Step 2 — Update knowledge base
    if not args.skip_kb_update:
        added = update_knowledge_base(events, dry_run=args.dry_run)
        logger.info("Knowledge base entries added: %d", added)
    else:
        logger.info("Knowledge base update skipped (--skip-kb-update)")

    # Summary
    logger.info("=" * 70)
    logger.info("COLLECTION SUMMARY")
    logger.info("=" * 70)
    logger.info("Total events collected : %d", len(events))
    by_source: Dict[str, int] = {}
    by_type: Dict[str, int] = {}
    for ev in events:
        by_source[ev["source"]] = by_source.get(ev["source"], 0) + 1
        by_type[ev["vuln_type"]] = by_type.get(ev["vuln_type"], 0) + 1
    logger.info("Events by source:")
    for src, cnt in sorted(by_source.items()):
        logger.info("  %-20s %d", src, cnt)
    logger.info("Events by vuln type (top 10):")
    for vtype, cnt in sorted(by_type.items(), key=lambda x: -x[1])[:10]:
        logger.info("  %-25s %d", vtype, cnt)
    logger.info("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
