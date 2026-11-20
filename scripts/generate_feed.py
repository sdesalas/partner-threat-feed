#!/usr/bin/env python3
"""Generate Partner Threat Feed rules.

The feed is one deterministic stream of rules: threat families, each with a few campaigns, each
campaign with a handful of indicator rules. --start and --count pick a slice of that stream, so the
first release and every later feed update come from the same stream without overlapping. All
indicators are synthetic and point at reserved address and domain ranges. See README.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import uuid
from collections import Counter
from pathlib import Path
from typing import Dict, Iterator, List, Tuple

FEED_NAMESPACE = uuid.UUID("3b9f6d1e-8c4a-4f27-b5e0-7a1d2c3e4f50")
LIBRARY_DIR = "rules"
SEED = "partner-threat-feed"

KINDS: Tuple[Tuple[str, str], ...] = (
    ("ransomware", "Ransomware"),
    ("infostealer", "Infostealer"),
    ("rat", "Remote Access Trojan"),
    ("loader", "Loader"),
    ("botnet", "Botnet"),
    ("banking_trojan", "Banking Trojan"),
    ("cryptominer", "Cryptominer"),
    ("phishing_kit", "Phishing Kit"),
    ("espionage", "Espionage Toolkit"),
)
ADJECTIVES = (
    "Ashen", "Brass", "Cedar", "Copper", "Dusky", "Flint", "Frosted", "Gilded", "Granite", "Hollow",
    "Ivory", "Juniper", "Linen", "Marble", "Mossy", "Nickel", "Ochre", "Pewter", "Quartz", "Russet",
    "Saffron", "Slate", "Tawny", "Umber", "Verdant", "Willow", "Walnut", "Birch", "Chalk", "Clay",
    "Driftwood", "Ember", "Fennel", "Hazel", "Lacquer", "Mulberry", "Oaken", "Paper", "Rosewood", "Tin",
)
NOUNS = (
    "Abacus", "Anvil", "Bellows", "Bobbin", "Kettle", "Ladle", "Lantern", "Loom", "Mortar", "Quill",
    "Sextant", "Spindle", "Teapot", "Thimble", "Trowel", "Whistle", "Easel", "Funnel", "Gimlet", "Hourglass",
    "Inkwell", "Jigsaw", "Keystone", "Lectern", "Mallet", "Needle", "Pestle", "Pulley", "Ratchet", "Satchel",
    "Shuttle", "Sieve", "Spool", "Stencil", "Tankard", "Tinderbox", "Trellis", "Turnstile", "Valise", "Wicket",
)
SYLLABLES = ("cdn", "sync", "mail", "auth", "edge", "data", "cloud", "update", "secure", "portal", "static",
             "api", "media", "files", "login", "track", "node", "relay", "assets", "connect")
TLDS = ("example", "test", "invalid")
SEVERITY = {"low": 21, "medium": 47, "high": 73, "critical": 99}
TACTICS = {
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "Command and Control": "TA0011",
}
DEFEND = {"package": "endpoint", "version": ">=8.2.0"}
NETWORK = {"package": "network_traffic", "version": ">=1.1.0"}
NETWORK_INDEX = ["logs-endpoint.events.network-*", "logs-network_traffic.*", "packetbeat-*"]
SYNTHETIC = "The indicators are synthetic and use reserved address and domain ranges, so they match no real traffic."


def technique(tid: str, name: str, sub: Tuple[str, str] | None = None) -> dict:
    entry: dict = {"id": tid, "name": name, "reference": f"https://attack.mitre.org/techniques/{tid}/"}
    if sub:
        entry["subtechnique"] = [
            {"id": sub[0], "name": sub[1], "reference": f"https://attack.mitre.org/techniques/{sub[0].replace('.', '/')}/"}
        ]
    return entry


def attack(tactic: str, entry: dict) -> List[dict]:
    tid = TACTICS[tactic]
    return [
        {
            "framework": "MITRE ATT&CK",
            "tactic": {"id": tid, "name": tactic, "reference": f"https://attack.mitre.org/tactics/{tid}/"},
            "technique": [entry],
        }
    ]


def kql_list(field: str, values: List[str]) -> str:
    return f"{field}:(" + " or ".join(f'"{value}"' for value in values) + ")"


def eql_list(values: List[str]) -> str:
    return "(" + ", ".join(f'"{value}"' for value in values) + ")"


class Indicators:
    def __init__(self, rng: random.Random, campaign: str):
        self.rng = rng
        self.campaign = campaign

    def count(self) -> int:
        return self.rng.randint(3, 8)

    def ips(self) -> List[str]:
        # 198.18.0.0/15 is reserved for benchmarking and never routed on the internet.
        return [f"198.{self.rng.randint(18, 19)}.{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}" for _ in range(self.count())]

    def domains(self) -> List[str]:
        return sorted({
            f"{self.rng.choice(SYLLABLES)}-{self.rng.choice(SYLLABLES)}{self.rng.randint(1, 99)}.{self.rng.choice(TLDS)}"
            for _ in range(self.count())
        })

    def hashes(self, label: str) -> List[str]:
        return [hashlib.sha256(f"{SEED}:{self.campaign}:{label}:{i}".encode()).hexdigest() for i in range(self.count())]

    def ja3(self) -> List[str]:
        return [hashlib.md5(f"{SEED}:{self.campaign}:ja3:{i}".encode()).hexdigest() for i in range(self.rng.randint(1, 3))]

    def urls(self) -> List[str]:
        paths = ("download", "invoice", "update", "gate", "payload", "doc", "install")
        return [
            f"https://{domain}/{self.rng.choice(paths)}/{self.rng.randint(1000, 9999)}.{self.rng.choice(('php', 'zip', 'bin', 'msi'))}"
            for domain in self.domains()
        ]

    def senders(self) -> List[str]:
        locals_ = ("billing", "noreply", "hr", "payroll", "support", "it-helpdesk", "accounts", "shipping")
        return sorted({f"{self.rng.choice(locals_)}@{domain}" for domain in self.domains()})

    def names(self, suffix: str = "") -> List[str]:
        words = ("Update", "Sync", "Helper", "Service", "Agent", "Monitor", "Host", "Broker", "Runtime", "Cache")
        return sorted({f"{self.rng.choice(words)}{self.rng.choice(words)}{suffix}" for _ in range(self.rng.randint(1, 3))})


def build_rule(template: str, family: str, kind: Tuple[str, str], campaign: str, ind: Indicators) -> dict:
    label = family_label(family, kind)
    attributes: dict = {}
    if template == "c2_ip":
        ips = ind.ips()
        attributes = dict(
            label="Connection to command and control IP address",
            what=f"network connections to command and control IP addresses used by the {label}",
            type="query", language="kuery", index=NETWORK_INDEX, integrations=[DEFEND, NETWORK], domain="Network",
            query=f"event.category:network and {kql_list('destination.ip', ips)}",
            severity="high", threat=attack("Command and Control", technique("T1071", "Application Layer Protocol")),
        )
    elif template == "c2_dns":
        attributes = dict(
            label="DNS lookup of command and control domain",
            what=f"DNS lookups of command and control domains used by the {label}",
            type="query", language="kuery", index=NETWORK_INDEX, integrations=[DEFEND, NETWORK], domain="Network",
            query=kql_list("dns.question.name", ind.domains()),
            severity="high", threat=attack("Command and Control", technique("T1071", "Application Layer Protocol", ("T1071.004", "DNS"))),
        )
    elif template == "file_hash":
        attributes = dict(
            label="File with known malicious hash written",
            what=f"files written to disk whose SHA-256 hash matches a {label} sample",
            type="query", language="kuery", index=["logs-endpoint.events.file-*"], integrations=[DEFEND], domain="Endpoint",
            query=f"event.category:file and {kql_list('file.hash.sha256', ind.hashes('file'))}",
            severity="high", threat=attack("Command and Control", technique("T1105", "Ingress Tool Transfer")),
        )
    elif template == "process_hash":
        attributes = dict(
            label="Process started from known malicious binary",
            what=f"processes started from binaries whose SHA-256 hash matches a {label} sample",
            type="eql", language="eql", index=["logs-endpoint.events.process-*"], integrations=[DEFEND], domain="Endpoint",
            query=f'process where event.type == "start" and process.hash.sha256 in {eql_list(ind.hashes("process"))}',
            severity="critical" if kind[0] == "ransomware" else "high",
            threat=attack("Execution", technique("T1204", "User Execution", ("T1204.002", "Malicious File"))),
        )
    elif template == "download_url":
        attributes = dict(
            label="Request to known payload URL",
            what=f"web requests to URLs that serve {label} payloads",
            type="query", language="kuery", index=["logs-network_traffic.http-*", "packetbeat-*", "logs-zscaler_zia.web-*"],
            integrations=[NETWORK], domain="Network",
            query=kql_list("url.full", ind.urls()),
            severity="medium", threat=attack("Command and Control", technique("T1105", "Ingress Tool Transfer")),
        )
    elif template == "tls_ja3":
        attributes = dict(
            label="TLS client fingerprint of implant",
            what=f"TLS connections whose JA3 client fingerprint matches the {label} implant",
            type="query", language="kuery", index=["logs-network_traffic.tls-*", "packetbeat-*"], integrations=[NETWORK],
            domain="Network", query=kql_list("tls.client.ja3", ind.ja3()),
            severity="medium", threat=attack("Command and Control", technique("T1573", "Encrypted Channel")),
        )
    elif template == "phishing_sender":
        attributes = dict(
            label="Email from known phishing sender",
            what=f"email messages from sender addresses used to deliver the {label}",
            type="query", language="kuery", index=["logs-email-*", "filebeat-*"], integrations=[], domain="Email",
            query=kql_list("email.from.address", ind.senders()),
            severity="medium", threat=attack("Initial Access", technique("T1566", "Phishing", ("T1566.001", "Spearphishing Attachment"))),
        )
    elif template == "run_key":
        values = ind.names()
        attributes = dict(
            label="Registry run key persistence",
            what=f"registry run key values that the {label} creates to start at logon",
            type="eql", language="eql", index=["logs-endpoint.events.registry-*"], integrations=[DEFEND], domain="Endpoint",
            query=(
                'registry where host.os.type == "windows" and event.type == "change" and '
                f'registry.value : {eql_list(values)} and '
                'registry.path : "*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\*"'
            ),
            severity="high", threat=attack("Persistence", technique("T1547", "Boot or Logon Autostart Execution", ("T1547.001", "Registry Run Keys / Startup Folder"))),
        )
    elif template == "scheduled_task":
        tasks = ind.names("Task")
        attributes = dict(
            label="Scheduled task created with known task name",
            what=f"scheduled tasks created with names that the {label} uses for persistence",
            type="eql", language="eql", index=["logs-endpoint.events.process-*"], integrations=[DEFEND], domain="Endpoint",
            query=(
                'process where host.os.type == "windows" and event.type == "start" and process.name : "schtasks.exe" and '
                f'process.args : ("/create", "-create") and process.args : {eql_list(tasks)}'
            ),
            severity="high", threat=attack("Persistence", technique("T1053", "Scheduled Task/Job", ("T1053.005", "Scheduled Task"))),
        )
    elif template == "dns_spread":
        domains = ind.domains()
        attributes = dict(
            label="Several hosts resolving command and control domains",
            what=f"three or more hosts resolving command and control domains used by the {label}",
            type="esql", language="esql", integrations=[DEFEND], domain="Network",
            query=(
                "FROM logs-endpoint.events.network-*\n"
                f"| WHERE dns.question.name IN {eql_list(domains)}\n"
                "| STATS host_count = COUNT_DISTINCT(host.id), hosts = VALUES(host.name) BY dns.question.name\n"
                "| WHERE host_count >= 3"
            ),
            severity="critical", threat=attack("Command and Control", technique("T1071", "Application Layer Protocol", ("T1071.004", "DNS"))),
        )
    elif template == "beaconing":
        attributes = dict(
            label="Repeated connections to command and control IP addresses",
            what=f"a host making 20 or more connections to command and control IP addresses used by the {label}",
            type="threshold", language="kuery", index=NETWORK_INDEX, integrations=[DEFEND, NETWORK], domain="Network",
            query=f"event.category:network and {kql_list('destination.ip', ind.ips())}",
            threshold={"field": ["host.id"], "value": 20},
            severity="high", threat=attack("Command and Control", technique("T1071", "Application Layer Protocol")),
        )
    elif template == "first_contact":
        attributes = dict(
            label="First connection from host to command and control domain",
            what=f"the first time a host connects to a command and control domain used by the {label}",
            type="new_terms", language="kuery", index=NETWORK_INDEX, integrations=[DEFEND, NETWORK], domain="Network",
            query=f"event.category:network and {kql_list('destination.domain', ind.domains())}",
            new_terms_fields=["host.id"], history_window_start="now-14d",
            severity="medium", threat=attack("Command and Control", technique("T1071", "Application Layer Protocol")),
        )
    return attributes


TEMPLATES = (
    "c2_ip", "c2_dns", "file_hash", "process_hash", "download_url", "tls_ja3",
    "phishing_sender", "run_key", "scheduled_task", "dns_spread", "beaconing", "first_contact",
)
TEMPLATE_WEIGHTS = (10, 10, 9, 9, 6, 4, 5, 5, 4, 2, 2, 2)


def make_rule(template: str, family: str, kind: Tuple[str, str], campaign: str, ind: Indicators) -> dict:
    spec = build_rule(template, family, kind, campaign, ind)
    rule_id = str(uuid.uuid5(FEED_NAMESPACE, f"{campaign}:{template}"))
    campaign_url = f"https://partner-threat-feed.example/campaigns/{campaign.lower()}"
    tactic = spec["threat"][0]["tactic"]["name"]
    tags = [
        f"Domain: {spec['domain']}",
        "Use Case: Threat Detection",
        f"Tactic: {tactic}",
        f"Threat: {family}",
        f"Threat Type: {kind[1]}",
        f"Campaign: {campaign}",
    ]
    if spec["domain"] == "Endpoint":
        tags.insert(1, "OS: Windows")
        tags.append("Data Source: Elastic Defend")
    elif spec["domain"] == "Network":
        tags.append("Data Source: Network Traffic")
    tags += ["Resources: Investigation Guide", "Source: Partner Threat Feed"]
    attributes = {
        "author": ["Partner Threat Feed"],
        "description": f"Identifies {spec['what']}, as reported in campaign {campaign}. {SYNTHETIC}",
        "false_positives": [
            "Security testing that replays known indicators.",
            "A shared hosting address or domain that later served benign content.",
        ],
        "from": "now-9m",
        "language": spec["language"],
        "license": "Elastic License v2",
        "name": f"{family} {kind[1]}: {spec['label']} ({campaign})",
        "note": (
            "## Triage and analysis\n\n"
            f"### Investigating {family} {kind[1]}: {spec['label']}\n\n"
            f"This rule matches indicators that the Partner Threat Feed attributes to the {family_label(family, kind)} "
            f"in campaign {campaign}.\n\n"
            "### Possible investigation steps\n\n"
            "- Review the matching event and the host or user it came from.\n"
            "- Look for other indicators from the same campaign on the same host.\n"
            "- Check the process tree around the event for the initial execution or delivery.\n\n"
            "### Response and remediation\n\n"
            "- Isolate the host if the match is confirmed.\n"
            "- Block the indicators at the network edge and on endpoints.\n"
            "- Reset credentials used on the host.\n"
        ),
        "query": spec["query"],
        "references": [campaign_url],
        "related_integrations": spec["integrations"],
        "risk_score": SEVERITY[spec["severity"]],
        "rule_id": rule_id,
        "severity": spec["severity"],
        "tags": tags,
        "threat": spec["threat"],
        "type": spec["type"],
        "version": 1,
    }
    if "index" in spec:
        attributes["index"] = spec["index"]
    if spec["type"] != "esql":
        attributes["timestamp_override"] = "event.ingested"
    for key in ("threshold", "new_terms_fields", "history_window_start"):
        if key in spec:
            attributes[key] = spec[key]
    return {"attributes": attributes, "id": f"{rule_id}_1", "type": "security-rule"}


def family_label(family: str, kind: Tuple[str, str]) -> str:
    return f"{family} {kind[1].lower()}"


def slug(text: str) -> str:
    return text.lower().replace(" ", "_").replace("-", "_")


def stream() -> Iterator[Tuple[str, dict]]:
    """Every rule of the feed, in feed order, as (path, rule)."""
    rng = random.Random(SEED)
    families = [f"{adjective} {noun}" for adjective in ADJECTIVES for noun in NOUNS]
    rng.shuffle(families)
    campaign_number = 0
    for index, family in enumerate(families):
        kind = KINDS[index % len(KINDS)]
        for _ in range(rng.randint(2, 6)):
            campaign_number += 1
            campaign = f"PTF-{campaign_number:05d}"
            ind = Indicators(rng, campaign)
            templates = sorted(
                set(rng.choices(TEMPLATES, weights=TEMPLATE_WEIGHTS, k=rng.randint(4, 9))), key=TEMPLATES.index
            )
            for template in templates:
                path = f"{LIBRARY_DIR}/{kind[0]}/{slug(family)}/{template}_{slug(campaign)}.json"
                yield path, make_rule(template, family, kind, campaign, ind)


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--start", type=int, default=0, help="position in the feed of the first rule to write")
    parser.add_argument("--count", type=int, default=12_000, help="number of rules to write")
    parser.add_argument("--apply", action="store_true", help="write the rule files (without it, only print the summary)")
    args = parser.parse_args()

    outputs: Dict[str, dict] = {}
    for position, (path, rule) in enumerate(stream()):
        if position >= args.start + args.count:
            break
        if position >= args.start:
            outputs[path] = rule
    if len(outputs) < args.count:
        raise SystemExit(f"The feed ends after {args.start + len(outputs)} rules")

    by_type = Counter(rule["attributes"]["type"] for rule in outputs.values())
    by_kind = Counter(path.split("/")[1] for path in outputs)
    families = {path.rsplit("/", 1)[0] for path in outputs}
    names = {rule["attributes"]["name"] for rule in outputs.values()}
    rule_ids = {rule["attributes"]["rule_id"] for rule in outputs.values()}
    print(f"Rules: {len(outputs)} (feed positions {args.start} to {args.start + args.count - 1})")
    print(f"Unique names: {len(names)}, unique rule ids: {len(rule_ids)}, families: {len(families)}")
    print(f"By type: {dict(by_type.most_common())}")
    print(f"By kind: {dict(by_kind.most_common())}")
    if len(names) != len(outputs) or len(rule_ids) != len(outputs):
        raise SystemExit("Rule names or ids are not unique")
    if not args.apply:
        print("Dry run: nothing written. Pass --apply to write the rule files.")
        return
    for path, rule in outputs.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(rule, indent=4, sort_keys=True))
    print(f"Wrote {len(outputs)} files under {root / LIBRARY_DIR}")


if __name__ == "__main__":
    main()
