#!/usr/bin/env python3
"""
JS Analyzer - analisi statica a regex dei JS scaricati da js_crawler
====================================================================
Cerca SEGRETI (chiavi API, token, chiavi private, JWT...) ed ENDPOINT (chiamate
HTTP, percorsi API, host interni, bucket cloud, GraphQL) nei file scaricati.

Le regole stanno in rules/*.toml nello stesso formato di gitleaks.toml:
  - rules/gitleaks.toml    (opzionale: scaricalo, vedi README sotto)
  - rules/extra_secrets.toml, rules/endpoints.toml, rules/overrides.toml

  curl -L -o rules/gitleaks.toml \\
    https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml

Uso:
  python js_analyzer.py js_downloads              # tutti i siti con manifest.jsonl
  python js_analyzer.py js_downloads/www.sito.it  # un sito
  python js_analyzer.py file.js altro.js          # file sciolti
  python js_analyzer.py --check-rules             # verifica che le regole compilino

Output (in <sito>/analysis/): findings.jsonl (valori COMPLETI, permessi 600),
endpoints.jsonl, endpoints.txt, report.md. In console i segreti sono mascherati.
Usalo solo su materiale raccolto da target per cui hai un'autorizzazione.
"""

from __future__ import annotations

import argparse
import base64
import bisect
import json
import logging
import math
import os
import re
import sys
import time
import warnings
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional
from urllib.parse import urlparse

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib  # pip install tomli

try:  # opzionale: supporta \p{..} e le classi POSIX che `re` non conosce
    import regex as regex_mod
except ImportError:
    regex_mod = None

VERSION = "1.0"
SEVERITIES = ["info", "low", "medium", "high", "critical"]
CONFIDENCES = ["low", "medium", "high"]
DEFAULT_RULES_DIR = Path(__file__).resolve().parent / "rules"
GITLEAKS_URL = "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"

PLACEHOLDER_TOKENS = (
    "example", "your_", "your-", "yourapi", "xxxx", "changeme", "placeholder", "dummy",
    "sample", "insert", "<", ">", "${", "{{", "process.env", "undefined",
)
VENDOR_NAME_RE = re.compile(
    r"(?:^|[/._~-])(?:jquery|bootstrap|angular|react(?:-dom)?|vue|lodash|underscore|moment|polyfills?|"
    r"vendors?|runtime|popper|swiper|slick|select2|datatables|fontawesome|core-js|zone|rxjs|gtm|gtag|"
    r"analytics|fbevents|hotjar|sentry|modernizr)(?:[._~-]|$)",
    re.I,
)
STATIC_EXT_RE = re.compile(
    r"\.(?:png|jpe?g|gif|svg|webp|ico|bmp|avif|css|scss|less|woff2?|ttf|eot|otf|mp[34]|webm|ogg|wav|map|js|mjs|pdf|zip|gz)"
    r"(?:[?#].*)?$",
    re.I,
)
VERBS = {"get", "post", "put", "patch", "delete", "head", "options"}
WINDOW_METHOD_RE = re.compile(r"""(?:method|type)\s*:\s*["'`](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["'`]""", re.I)
TAG_PATTERNS = [
    ("graphql", re.compile(r"graphql|/gql", re.I)),
    ("auth", re.compile(r"auth|login|logout|sign[-_]?(?:in|up)|token|oauth|sso|saml|session|password|2fa|mfa", re.I)),
    ("admin", re.compile(r"admin|backoffice|manage|console|internal", re.I)),
    ("debug", re.compile(r"debug|actuator|swagger|openapi|api-docs|phpinfo|trace|metrics|health|\.env|\.git", re.I)),
    ("upload", re.compile(r"upload|attachment|import", re.I)),
    ("user", re.compile(r"user|account|profile|customer", re.I)),
    ("payment", re.compile(r"payment|checkout|billing|invoice|order", re.I)),
]


# =============================================================================
# Utilita'
# =============================================================================
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def mask(s: str) -> str:
    if s.startswith("-----BEGIN"):
        return f"-----BEGIN...[{len(s)} caratteri]"
    if len(s) <= 8:
        return "*" * len(s)
    if len(s) <= 16:
        return f"{s[:2]}...{s[-2:]}"
    return f"{s[:4]}...{s[-4:]}"


def is_placeholder(secret: str) -> bool:
    low = secret.lower()
    if any(tok in low for tok in PLACEHOLDER_TOKENS):
        return True
    return len(set(secret)) <= 2  # 'aaaaaaaa', '12121212'


def _b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def validate_jwt(token: str) -> Optional[dict]:
    """None se non e' un vero JWT (falso positivo); altrimenti un dizionario di dettagli."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url(parts[0]))
        payload = json.loads(_b64url(parts[1]))
    except Exception:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    d: dict = {"alg": header.get("alg"), "typ": header.get("typ")}
    for k in ("iss", "sub", "aud", "exp", "iat"):
        if k in payload:
            d[k] = payload[k]
    if isinstance(payload.get("exp"), (int, float)):
        d["expired"] = payload["exp"] < time.time()
    if str(header.get("alg", "")).lower() == "none":
        d["alg_none"] = True
    return d


VALIDATORS = {"jwt": validate_jwt}
VALIDATOR_BY_ID = {"jwt": "jwt", "jwt-base64": "jwt"}  # id gitleaks -> validatore


def _sev_index(s: str) -> int:
    return SEVERITIES.index(s) if s in SEVERITIES else 0


def _downgrade(conf: str) -> str:
    return CONFIDENCES[max(0, CONFIDENCES.index(conf) - 1)] if conf in CONFIDENCES else "low"


# =============================================================================
# Regole
# =============================================================================
_POSIX_CLASSES = {
    "alpha": "a-zA-Z", "digit": "0-9", "alnum": "a-zA-Z0-9", "upper": "A-Z", "lower": "a-z",
    "space": r"\s", "word": r"\w", "blank": r" \t", "xdigit": "0-9A-Fa-f",
    "punct": r"!-/:-@\[-`{-~", "cntrl": r"\x00-\x1f\x7f", "print": r"\x20-\x7e", "graph": r"\x21-\x7e",
}
_POSIX_RE = re.compile(r"\[:(\w+):\]")


def _translate_posix(p: str) -> str:
    """Go/RE2 capisce [[:alpha:]]; Python la leggerebbe come un insieme di caratteri sbagliato."""
    return _POSIX_RE.sub(lambda m: _POSIX_CLASSES.get(m.group(1), m.group(0)), p)


def compile_regex(pattern: str, log: logging.Logger, label: str, failures: Optional[list] = None,
                  notes: Optional[list] = None):
    """Compila una regex in stile Go/RE2. Ritorna None (e registra il motivo) se non e' compatibile.
    `notes` raccoglie le regole adattate (classi POSIX) o compilate con avvisi di sintassi."""
    p = pattern.replace("\\z", "\\Z")
    p = re.sub(r"\(\?<([A-Za-z_]\w*)>", r"(?P<\1>", p)  # (?<nome>) -> (?P<nome>)
    translated = _translate_posix(p)
    if translated != p:
        if notes is not None:
            notes.append((label, "classi POSIX [[:x:]] tradotte per Python"))
        p = translated
    err: Optional[Exception] = None
    for mod in (re, regex_mod):
        if mod is None:
            continue
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                rx = mod.compile(p)
        except Exception as e:  # noqa: BLE001
            err = e
            continue
        if caught and notes is not None:
            notes.append((label, "avviso di sintassi: " + str(caught[0].message)))
        return rx
    if failures is not None:
        failures.append((label, str(err)[:120]))
    log.debug("regex non compilabile (%s): %s", label, err)
    return None


@dataclass
class Allowlist:
    regexes: list = field(default_factory=list)
    stopwords: list = field(default_factory=list)
    paths: list = field(default_factory=list)
    target: str = "secret"
    condition: str = "OR"

    def hits(self, secret: str, match: str, line: str, path: str, use_paths: bool = True) -> bool:
        checks = []
        if self.paths and use_paths:
            checks.append(any(p.search(path) for p in self.paths))
        if self.regexes:
            target = {"match": match, "line": line}.get(self.target, secret)
            checks.append(any(r.search(target) for r in self.regexes))
        if self.stopwords:
            low = secret.lower()
            checks.append(any(w in low for w in self.stopwords))
        if not checks:
            return False
        return all(checks) if self.condition == "AND" else any(checks)


@dataclass
class Rule:
    id: str
    regex: object
    description: str = ""
    kind: str = "secret"  # secret | endpoint | url | infra | graphql
    category: str = "secret"
    severity: str = "high"
    confidence: str = "high"
    secret_group: int = 0
    entropy: float = 0.0
    keywords: list = field(default_factory=list)
    allowlists: list = field(default_factory=list)
    path_re: object = None
    validator: Optional[str] = None
    aggressive: bool = False
    window_method: bool = False
    exclude_hosts: list = field(default_factory=list)
    note: str = ""
    source: str = ""

    @property
    def group(self) -> str:
        return "secrets" if self.kind == "secret" else "endpoints"


@dataclass
class RuleSet:
    rules: list
    global_allowlists: list
    failures: list
    files: list
    notes: list = field(default_factory=list)


def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _parse_allowlists(container: dict, comp) -> list:
    out = []
    for key in ("allowlist", "allowlists"):
        for d in _as_list(container.get(key)):
            if not isinstance(d, dict):
                continue
            out.append(
                Allowlist(
                    regexes=[c for c in (comp(x, "allowlist") for x in _as_list(d.get("regexes"))) if c],
                    stopwords=[str(w).lower() for w in _as_list(d.get("stopwords"))],
                    paths=[c for c in (comp(x, "allowlist-path") for x in _as_list(d.get("paths"))) if c],
                    target=str(d.get("regexTarget") or "secret").lower(),
                    condition=str(d.get("condition") or "OR").upper(),
                )
            )
    return out


def load_rules_file(path: Path, log: logging.Logger, failures: list, notes: Optional[list] = None):
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as e:
        log.error("Impossibile leggere %s: %s", path, e)
        failures.append((path.name, f"TOML non valido: {e}"))
        return [], []

    def comp(pattern, label):
        return compile_regex(str(pattern), log, f"{path.name}:{label}", failures, notes)

    global_als = _parse_allowlists(data, comp)
    rules = []
    for raw in data.get("rules", []):
        rid, pattern = raw.get("id"), raw.get("regex")
        if not rid or not pattern:
            continue  # regole "solo path": non ci servono
        rx = compile_regex(str(pattern), log, rid, failures, notes)
        if rx is None:
            continue
        kind = str(raw.get("kind", "secret")).lower()
        is_generic = "generic" in rid
        sev = str(raw.get("severity", "medium" if is_generic else ("high" if kind == "secret" else "info"))).lower()
        conf = str(raw.get("confidence", "low" if is_generic else "high")).lower()
        path_re = comp(raw["path"], f"{rid}:path") if raw.get("path") else None
        rules.append(
            Rule(
                id=rid,
                regex=rx,
                description=str(raw.get("description", "")),
                kind=kind,
                category=str(raw.get("category", "secret" if kind == "secret" else kind)),
                severity=sev if sev in SEVERITIES else "medium",
                confidence=conf if conf in CONFIDENCES else "medium",
                secret_group=int(raw.get("secretGroup", 0) or 0),
                entropy=float(raw.get("entropy", 0) or 0),
                keywords=[str(k).lower() for k in _as_list(raw.get("keywords"))],
                allowlists=_parse_allowlists(raw, comp),
                path_re=path_re,
                validator=raw.get("validator") or VALIDATOR_BY_ID.get(rid),
                aggressive=bool(raw.get("aggressive", False)),
                window_method=bool(raw.get("window_method", False)),
                exclude_hosts=[str(h).lower() for h in _as_list(raw.get("exclude_hosts"))],
                source=path.name,
            )
        )
    return rules, global_als


def load_ruleset(rules_dir: Path, log: logging.Logger, extra_files=()) -> RuleSet:
    failures: list = []
    notes: list = []
    files = [p for p in sorted(Path(rules_dir).glob("*.toml")) if p.name != "overrides.toml"]
    files.sort(key=lambda p: (p.name != "gitleaks.toml", p.name))  # gitleaks per primo: le nostre lo sovrascrivono
    files += [Path(f) for f in extra_files]
    by_id: dict = {}
    global_als: list = []
    for f in files:
        rules, als = load_rules_file(f, log, failures, notes)
        global_als += als
        for r in rules:
            by_id[r.id] = r  # stesso id -> vince il file caricato dopo
    ov_path = Path(rules_dir) / "overrides.toml"
    if ov_path.exists():
        try:
            ov = tomllib.loads(ov_path.read_text(encoding="utf-8")).get("overrides", {})
            for rid, o in ov.items():
                r = by_id.get(rid)
                if not r:
                    continue
                if o.get("severity") in SEVERITIES:
                    r.severity = o["severity"]
                if o.get("confidence") in CONFIDENCES:
                    r.confidence = o["confidence"]
                r.note = str(o.get("note", r.note))
        except (OSError, tomllib.TOMLDecodeError) as e:
            log.error("overrides.toml non valido: %s", e)
    return RuleSet(list(by_id.values()), global_als, failures, [f.name for f in files], notes)


# =============================================================================
# Normalizzazione leggera (ricostruisce cio' che l'offuscamento banale nasconde)
# =============================================================================
_ESC_X = re.compile(r"\\x([0-9a-fA-F]{2})")
_ESC_U = re.compile(r"\\u([0-9a-fA-F]{4})")
_CONCAT = re.compile(
    r"""(?P<q>["'])(?P<a>(?:(?!(?P=q))[^\\\n])*)(?P=q)\s*\+\s*(?P=q)(?P<b>(?:(?!(?P=q))[^\\\n])*)(?P=q)"""
)
_ATOB = re.compile(r"""atob\(\s*["']([A-Za-z0-9+/=]{16,})["']\s*\)""")


def normalize_js(text: str):
    """Ritorna (testo normalizzato o None se invariato, lista di stringhe da atob())."""
    t, changed = text, False
    if "\\x" in t or "\\u" in t:
        t2 = _ESC_X.sub(lambda m: chr(int(m.group(1), 16)), t)
        t2 = _ESC_U.sub(lambda m: chr(int(m.group(1), 16)), t2)
        changed, t = changed or t2 != t, t2
    if "+" in t:
        for _ in range(4):
            t2 = _CONCAT.sub(lambda m: m.group("q") + m.group("a") + m.group("b") + m.group("q"), t)
            if t2 == t:
                break
            t, changed = t2, True
    decoded = []
    if "atob" in text:
        for m in _ATOB.finditer(text):
            try:
                d = base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4)).decode("utf-8", "ignore")
            except Exception:  # noqa: BLE001
                continue
            if d.strip():
                decoded.append(d)
    return (t if changed else None), decoded


# =============================================================================
# Endpoint: normalizzazione e filtri
# =============================================================================
def normalize_endpoint(value: str) -> str:
    v = value.strip().replace("\\/", "/")
    v = re.sub(r"\$\{[^}]*\}", "{param}", v)
    v = re.sub(r"(?:\{param\}){2,}", "{param}", v)
    v = re.sub(r"^\{param\}(?=/)", "", v)  # `${baseUrl}/api/x` -> /api/x
    return v


def looks_like_endpoint(v: str, kind: str) -> bool:
    if not (2 <= len(v) <= 300) or re.search(r"[\s<>]", v):
        return False
    if v.lower().startswith(("data:", "javascript:", "mailto:", "tel:", "blob:", "#", "about:")):
        return False
    if kind in ("infra", "graphql"):
        return True
    if STATIC_EXT_RE.search(v) or re.fullmatch(r"(?:\{param\}|[/.?&=#-])*", v):
        return False
    if kind == "endpoint":
        return v.startswith(("/", "http://", "https://", "ws://", "wss://")) or "/" in v
    return True


def infer_method(rule: Rule, m, text: str) -> str:
    gd = m.groupdict()
    if gd.get("method"):
        return gd["method"].upper()
    fn = gd.get("fn") or ""
    if fn:
        tail = fn.split(".")[-1].lower()
        if tail == "getjson":
            return "GET"
        if tail in VERBS:
            return tail.upper()
    if rule.window_method:
        wm = WINDOW_METHOD_RE.search(text[m.end(): m.end() + 200])
        if wm:
            return wm.group(1).upper()
    return "?"


def endpoint_tags(value: str) -> list:
    return [name for name, rx in TAG_PATTERNS if rx.search(value)]


def resolve_url(value: str, file_url: Optional[str]) -> Optional[str]:
    if re.match(r"^(?:https?|wss?)://", value):
        return value
    if value.startswith("/") and file_url:
        p = urlparse(file_url)
        if p.scheme and p.netloc:
            return f"{p.scheme}://{p.netloc}{value}"
    return None


# =============================================================================
# Motore di analisi
# =============================================================================
@dataclass
class AnalyzerOptions:
    only: str = "all"  # all | secrets | endpoints
    min_severity: str = "info"
    skip_vendor: bool = False
    include_node_modules: bool = False
    normalize: bool = True
    aggressive: bool = False
    max_matches: int = 200
    max_file_size: int = 50 * 1024 * 1024
    show_secrets: bool = False
    no_path_allowlist: bool = False


def pick_secret(m, group: int) -> str:
    if group and group <= m.re.groups and m.group(group):
        return m.group(group)
    for i in range(1, m.re.groups + 1):
        if m.group(i):
            return m.group(i)
    return m.group(0)


class Analyzer:
    def __init__(self, ruleset: RuleSet, opts: AnalyzerOptions, log: logging.Logger):
        self.rs, self.opts, self.log = ruleset, opts, log
        self.rules = [
            r for r in ruleset.rules
            if (opts.aggressive or not r.aggressive) and opts.only in ("all", r.group)
        ]
        self.secrets: dict = {}
        self.endpoints: dict = {}
        self.stats: Counter = Counter()

    # --------------------------------------------------------------- file
    def scan_file(self, relpath: str, url: Optional[str], text: str, third_party: bool = False, vendor: bool = False):
        self.stats["files"] += 1
        seen_in_file: set = set()
        self._scan(text, relpath, url, third_party, vendor, "original", seen_in_file)
        if self.opts.normalize:
            norm, decoded = normalize_js(text)
            if norm is not None:
                self._scan(norm, relpath, url, third_party, vendor, "normalized", seen_in_file)
            for d in decoded[:20]:
                self._scan(d, relpath, url, third_party, vendor, "atob", seen_in_file)

    def _allowlisted(self, rule: Rule, secret: str, match_text: str, line: str, relpath: str) -> bool:
        use_paths = not self.opts.no_path_allowlist
        return any(
            al.hits(secret, match_text, line, relpath, use_paths)
            for al in rule.allowlists + self.rs.global_allowlists
        )

    def _scan(self, text, relpath, url, third_party, vendor, variant, seen_in_file):
        opts = self.opts
        low = text.lower()
        nl_cache: list = []

        def locate(pos: int):
            if not nl_cache:
                nl_cache.append([m.start() for m in re.finditer("\n", text)])
            nl = nl_cache[0]
            idx = bisect.bisect_right(nl, pos)
            line_start = nl[idx - 1] + 1 if idx else 0
            return idx + 1, pos - line_start + 1

        for rule in self.rules:
            if rule.path_re and not rule.path_re.search(relpath):
                continue
            if rule.keywords and not any(k in low for k in rule.keywords):
                continue
            count = 0
            for m in rule.regex.finditer(text):
                count += 1
                if count > opts.max_matches:
                    self.stats["rule_match_cap_hit"] += 1
                    break
                if rule.kind == "secret":
                    self._handle_secret(rule, m, text, relpath, url, third_party, vendor, variant, seen_in_file, locate)
                else:
                    self._handle_endpoint(rule, m, text, relpath, url, third_party, vendor, variant, locate)

    # ------------------------------------------------------------ segreti
    def _handle_secret(self, rule, m, text, relpath, url, third_party, vendor, variant, seen_in_file, locate):
        secret = pick_secret(m, rule.secret_group)
        if not secret:
            return
        if variant != "original" and secret in seen_in_file:
            return
        ent = shannon_entropy(secret)
        if rule.entropy and ent < rule.entropy:
            self.stats["scartati_entropia"] += 1
            return
        if is_placeholder(secret):
            self.stats["scartati_placeholder"] += 1
            return
        s, e = m.start(), m.end()
        ls = max(text.rfind("\n", 0, s) + 1, s - 300)
        le_raw = text.find("\n", e)
        le = min(len(text) if le_raw < 0 else le_raw, e + 300)
        if self._allowlisted(rule, secret, m.group(0), text[ls:le], relpath):
            self.stats["scartati_allowlist"] += 1
            return
        details = None
        severity, confidence = rule.severity, rule.confidence
        if rule.validator in VALIDATORS:
            details = VALIDATORS[rule.validator](secret)
            if details is None:
                self.stats["scartati_validatore"] += 1
                return
            if details.get("alg_none"):
                severity = "high"
            elif details.get("expired") is True and _sev_index(severity) > _sev_index("low"):
                severity = "low"
        if third_party or vendor:
            confidence = _downgrade(confidence)
        line, col = locate(s)
        snippet = re.sub(r"\s+", " ", text[max(0, s - 60): e + 60])
        seen_in_file.add(secret)
        self._add_secret(
            {
                "category": rule.category, "rule_id": rule.id, "description": rule.description,
                "severity": severity, "confidence": confidence, "secret": secret,
                "secret_masked": mask(secret), "entropy": round(ent, 2), "note": rule.note,
                "details": details, "snippet": snippet, "third_party": third_party, "vendor": vendor,
            },
            {"file": relpath, "url": url, "line": line, "col": col, "variant": variant},
        )

    def _add_secret(self, f: dict, loc: dict) -> None:
        key = (f["category"], f["secret"])
        cur = self.secrets.get(key)
        if cur is None:
            f["rules"] = {f["rule_id"]}
            f["occurrences"] = 1
            f["locations"] = [loc]
            self.secrets[key] = f
            return
        cur["rules"].add(f["rule_id"])
        cur["occurrences"] += 1
        if len(cur["locations"]) < 10:
            cur["locations"].append(loc)
        if _sev_index(f["severity"]) > _sev_index(cur["severity"]):
            for k in ("severity", "rule_id", "description", "note"):
                cur[k] = f[k]
        if CONFIDENCES.index(f["confidence"]) > CONFIDENCES.index(cur["confidence"]):
            cur["confidence"] = f["confidence"]

    # ----------------------------------------------------------- endpoint
    def _handle_endpoint(self, rule, m, text, relpath, url, third_party, vendor, variant, locate):
        gd = m.groupdict()
        raw = gd.get("url")
        if raw is None:
            raw = pick_secret(m, rule.secret_group)
        if not raw:
            return
        value = normalize_endpoint(raw)
        if rule.kind in ("endpoint", "url") and text[m.end(): m.end() + 4].lstrip().startswith("+"):
            value += "{param}"  # "/api/users/" + id
        if not looks_like_endpoint(value, rule.kind):
            return
        full = resolve_url(value, url) if rule.kind != "graphql" else None
        host = urlparse(full).hostname if full else None
        if rule.exclude_hosts and host:
            h = host.lower()
            if any(h == x or h.endswith("." + x) for x in rule.exclude_hosts):
                return
        method = infer_method(rule, m, text)
        line, col = locate(m.start())
        key = value if rule.kind != "graphql" else f"graphql:{value}"
        cur = self.endpoints.get(key)
        if cur is None:
            cur = self.endpoints[key] = {
                "value": value, "kind": rule.kind, "category": rule.category, "full_url": full, "host": host,
                "methods": set(), "rules": set(), "tags": set(endpoint_tags(value)),
                "severity": rule.severity, "occurrences": 0, "sources": [],
                "third_party": third_party or vendor,
            }
        cur["methods"].add(method)
        cur["rules"].add(rule.id)
        cur["occurrences"] += 1
        if _sev_index(rule.severity) > _sev_index(cur["severity"]):
            cur["severity"] = rule.severity
        if rule.id == "internal-host":
            cur["tags"].add("internal")
        src = {"file": relpath, "url": url, "line": line}
        if len(cur["sources"]) < 10 and src not in cur["sources"]:
            cur["sources"].append(src)
        if not (third_party or vendor):
            cur["third_party"] = False


# =============================================================================
# Input: manifest del crawler, sourcemap, file sciolti
# =============================================================================
def _read_text(path: Path, max_size: int) -> Optional[str]:
    try:
        if path.stat().st_size > max_size:
            return None
        return path.read_bytes().decode("utf-8", "replace")
    except OSError:
        return None


def _iter_sourcemap(rec: dict, saved: str, path: Path, opts: AnalyzerOptions, log: logging.Logger):
    text = _read_text(path, opts.max_file_size)
    if not text:
        return
    try:
        data = json.loads(text)
    except ValueError:
        return
    sources = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    url = rec.get("final_url") or rec.get("url")
    for i, name in enumerate(sources):
        content = contents[i] if i < len(contents) else None
        if not content:
            continue
        nm = str(name)
        nm_vendor = "node_modules" in nm
        if nm_vendor and not opts.include_node_modules:
            continue
        yield {
            "relpath": f"{saved}::{nm}", "url": url, "text": content,
            "third_party": not rec.get("in_scope", True),
            "vendor": nm_vendor or bool(VENDOR_NAME_RE.search(nm)),
        }


def iter_site_inputs(site_dir: Path, opts: AnalyzerOptions, log: logging.Logger) -> Iterator[dict]:
    seen: set = set()
    for line in (site_dir / "manifest.jsonl").read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        saved = rec.get("saved_path")
        if rec.get("status") not in ("ok", "suspicious_saved") or not saved or saved in seen:
            continue
        seen.add(saved)
        path = site_dir / saved
        if rec.get("source") == "sourcemap" or saved.endswith(".map"):
            yield from _iter_sourcemap(rec, saved, path, opts, log)
            continue
        text = _read_text(path, opts.max_file_size)
        if text is None:
            log.debug("saltato (illeggibile o troppo grande): %s", saved)
            continue
        yield {
            "relpath": saved, "url": rec.get("final_url") or rec.get("url"), "text": text,
            "third_party": not rec.get("in_scope", True), "vendor": bool(VENDOR_NAME_RE.search(saved)),
        }


def iter_loose_inputs(paths: list, opts: AnalyzerOptions) -> Iterator[dict]:
    for p in paths:
        p = Path(p)
        files = [p] if p.is_file() else sorted(x for x in p.rglob("*") if x.is_file())
        for f in files:
            if f.suffix.lower() not in (".js", ".mjs", ".map", ".json"):
                continue
            if f.suffix.lower() == ".map":
                rec = {"url": None, "in_scope": True}
                yield from _iter_sourcemap(rec, str(f), f, opts, logging.getLogger("jsanalyzer"))
                continue
            text = _read_text(f, opts.max_file_size)
            if text is not None:
                yield {"relpath": str(f), "url": None, "text": text, "third_party": False,
                       "vendor": bool(VENDOR_NAME_RE.search(str(f)))}


# =============================================================================
# Output
# =============================================================================
def _jsonable_secret(f: dict) -> dict:
    out = dict(f)
    out["rules"] = sorted(f["rules"])
    return out


def _jsonable_endpoint(e: dict) -> dict:
    out = dict(e)
    methods = set(e["methods"])
    if len(methods) > 1:
        methods.discard("?")
    out["methods"] = sorted(methods)
    out["rules"] = sorted(e["rules"])
    out["tags"] = sorted(e["tags"])
    return out


def write_outputs(out_dir: Path, analyzer: Analyzer, label: str, opts: AnalyzerOptions, ruleset: RuleSet) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    min_idx = _sev_index(opts.min_severity)
    secrets = [f for f in analyzer.secrets.values() if _sev_index(f["severity"]) >= min_idx]
    secrets.sort(key=lambda f: (-_sev_index(f["severity"]), -CONFIDENCES.index(f["confidence"]), f["rule_id"]))
    endpoints = [_jsonable_endpoint(e) for e in analyzer.endpoints.values()]
    endpoints.sort(key=lambda e: (-_sev_index(e["severity"]), -len(e["tags"]), e["value"]))

    fpath = out_dir / "findings.jsonl"
    with open(fpath, "w", encoding="utf-8") as fh:
        for f in secrets:
            fh.write(json.dumps(_jsonable_secret(f), ensure_ascii=False) + "\n")
    try:
        os.chmod(fpath, 0o600)  # contiene i valori completi dei segreti
    except OSError:
        pass
    with open(out_dir / "endpoints.jsonl", "w", encoding="utf-8") as fh:
        for e in endpoints:
            fh.write(json.dumps(e, ensure_ascii=False) + "\n")
    lines = sorted({e["full_url"] or e["value"] for e in endpoints if e["kind"] in ("endpoint", "url", "infra")})
    (out_dir / "endpoints.txt").write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    by_sev = Counter(f["severity"] for f in secrets)
    stats = {
        "label": label, "files_scanned": analyzer.stats["files"], "secrets": len(secrets),
        "secrets_by_severity": dict(by_sev), "endpoints": len(endpoints),
        "discarded": {k: v for k, v in analyzer.stats.items() if k.startswith("scartati") or k == "rule_match_cap_hit"},
        "rules_active": len(analyzer.rules), "rule_files": ruleset.files,
    }
    _write_report(out_dir / "report.md", stats, secrets, endpoints, opts)
    return stats


def _write_report(path: Path, stats: dict, secrets: list, endpoints: list, opts: AnalyzerOptions) -> None:
    L = [f"# JS Analyzer - {stats['label']}", "",
         f"- File analizzati: {stats['files_scanned']}  |  regole attive: {stats['rules_active']} ({', '.join(stats['rule_files'])})",
         f"- Segreti: {stats['secrets']} {stats['secrets_by_severity']}  |  endpoint: {stats['endpoints']}",
         f"- Scartati dai filtri: {stats['discarded']}", "", "## Segreti (valori mascherati)", ""]
    if not secrets:
        L.append("Nessun segreto trovato.")
    for f in secrets[:100]:
        loc = f["locations"][0]
        L.append(f"- **[{f['severity'].upper()}/{f['confidence']}]** `{f['rule_id']}` `{f['secret_masked']}` "
                 f"x{f['occurrences']} - {loc['url'] or loc['file']} (riga {loc['line']}, {loc['variant']})")
        if f.get("note"):
            L.append(f"  - {f['note']}")
        if f.get("details"):
            L.append(f"  - dettagli: {f['details']}")
    L += ["", "## Endpoint interessanti (con tag)", ""]
    tagged = [e for e in endpoints if e["tags"] and e["kind"] in ("endpoint", "url", "infra", "graphql")]
    for e in tagged[:150]:
        L.append(f"- `{','.join(e['methods'])}` {e['full_url'] or e['value']}  [{', '.join(e['tags'])}]")
    if not tagged:
        L.append("Nessuno.")
    L += ["", f"Elenco completo in `endpoints.txt` / `endpoints.jsonl` ({len(endpoints)} voci)."]
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


# =============================================================================
# Orchestrazione
# =============================================================================
def analyze_inputs(inputs: Iterator[dict], ruleset: RuleSet, opts: AnalyzerOptions, log: logging.Logger) -> Analyzer:
    an = Analyzer(ruleset, opts, log)
    t0 = time.monotonic()
    for item in inputs:
        if opts.skip_vendor and (item["vendor"] or item["third_party"]):
            an.stats["file_saltati_vendor"] += 1
            continue
        an.scan_file(item["relpath"], item["url"], item["text"], item["third_party"], item["vendor"])
    log.debug("analisi completata in %.1fs", time.monotonic() - t0)
    return an


def print_summary(an: Analyzer, opts: AnalyzerOptions, log: logging.Logger, limit: int = 25) -> None:
    min_idx = _sev_index(opts.min_severity)
    shown = sorted(
        (f for f in an.secrets.values() if _sev_index(f["severity"]) >= min_idx),
        key=lambda f: (-_sev_index(f["severity"]), -CONFIDENCES.index(f["confidence"])),
    )
    for f in shown[:limit]:
        loc = f["locations"][0]
        val = f["secret"] if opts.show_secrets else f["secret_masked"]
        log.info("[%s/%s] %s %s x%d  %s:%d", f["severity"].upper(), f["confidence"], f["rule_id"], val,
                 f["occurrences"], loc["url"] or loc["file"], loc["line"])
    if len(shown) > limit:
        log.info("... altri %d segreti nel report", len(shown) - limit)


_RULESET_CACHE: dict = {}


def analyze_site(site_dir: Path, ruleset: RuleSet, opts: AnalyzerOptions, log: logging.Logger) -> dict:
    site_dir = Path(site_dir)
    an = analyze_inputs(iter_site_inputs(site_dir, opts, log), ruleset, opts, log)
    stats = write_outputs(site_dir / "analysis", an, site_dir.name, opts, ruleset)
    log.info("Analisi %s: %d file, %d segreti, %d endpoint -> %s", site_dir.name, stats["files_scanned"],
             stats["secrets"], stats["endpoints"], site_dir / "analysis")
    print_summary(an, opts, log)
    return stats


def analyze_from_crawler(site_dir: Path, rules_dir: Optional[str], log: logging.Logger) -> dict:
    """Entry point usato da js_crawler --analyze."""
    rd = Path(rules_dir) if rules_dir else DEFAULT_RULES_DIR
    if str(rd) not in _RULESET_CACHE:
        _RULESET_CACHE[str(rd)] = load_ruleset(rd, log)
        _warn_if_no_gitleaks(_RULESET_CACHE[str(rd)], rd, log)
    return analyze_site(site_dir, _RULESET_CACHE[str(rd)], AnalyzerOptions(), log)


def _warn_if_no_gitleaks(rs: RuleSet, rules_dir: Path, log: logging.Logger) -> None:
    if "gitleaks.toml" not in rs.files:
        log.warning("rules/gitleaks.toml non trovato: uso solo le regole incluse. Per le regole di gitleaks:\n  curl -L -o %s %s",
                    rules_dir / "gitleaks.toml", GITLEAKS_URL)


def discover_sites(root: Path) -> list:
    if (root / "manifest.jsonl").exists():
        return [root]
    return sorted(d for d in root.iterdir() if d.is_dir() and (d / "manifest.jsonl").exists()) if root.is_dir() else []


def setup_logging(verbose: bool) -> logging.Logger:
    log = logging.getLogger("jsanalyzer")
    log.setLevel(logging.DEBUG)
    log.handlers.clear()
    h = logging.StreamHandler()
    h.setLevel(logging.DEBUG if verbose else logging.INFO)
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%H:%M:%S"))
    log.addHandler(h)
    return log


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="JS Analyzer - cerca segreti ed endpoint nei JS scaricati (regex).")
    p.add_argument("inputs", nargs="*", help="cartella output del crawler, cartella di un sito, o file .js/.map sciolti (default: js_downloads)")
    p.add_argument("--rules-dir", default=str(DEFAULT_RULES_DIR), help="cartella con i file di regole .toml")
    p.add_argument("--only", choices=["all", "secrets", "endpoints"], default="all")
    p.add_argument("--min-severity", choices=SEVERITIES, default="info", help="mostra solo segreti da questa severita' in su")
    p.add_argument("--skip-vendor", action="store_true", help="salta librerie vendor e JS di terze parti")
    p.add_argument("--include-node-modules", action="store_true", help="analizza anche i sorgenti node_modules delle sourcemap")
    p.add_argument("--no-normalize", action="store_true", help="non ricostruire stringhe concatenate/escape/atob")
    p.add_argument("--aggressive", action="store_true", help="abilita le regole rumorose (aggressive = true)")
    p.add_argument("--max-matches", type=int, default=200, help="massimo match per regola per file (default 200)")
    p.add_argument("--max-file-size", type=int, default=50 * 1024 * 1024, help="salta file piu' grandi (byte)")
    p.add_argument("--show-secrets", action="store_true", help="mostra i valori in chiaro in console")
    p.add_argument("--no-path-allowlist", action="store_true", help="ignora le allowlist per percorso delle regole")
    p.add_argument("-o", "--output-dir", help="per file sciolti: cartella di output (default: analysis_out)")
    p.add_argument("--check-rules", action="store_true", help="carica le regole, riporta quelle non compatibili ed esci")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    log = setup_logging(args.verbose)
    rules_dir = Path(args.rules_dir)
    rs = load_ruleset(rules_dir, log)

    if args.check_rules:
        kinds = Counter(r.kind for r in rs.rules)
        print(f"File di regole: {', '.join(rs.files) or '(nessuno)'}")
        print(f"Regole caricate: {len(rs.rules)} {dict(kinds)} | allowlist globali: {len(rs.global_allowlists)}")
        if "gitleaks.toml" not in rs.files:
            print(f"gitleaks.toml assente. Scaricalo con:\n  curl -L -o {rules_dir / 'gitleaks.toml'} {GITLEAKS_URL}")
        if rs.failures:
            print(f"\n{len(rs.failures)} regole/allowlist NON compilabili in Python (ignorate):")
            for label, reason in rs.failures:
                print(f"  - {label}: {reason}")
            if regex_mod is None:
                print("\nSuggerimento: `pip install regex` supporta \\p{..} e le classi POSIX usate da Go.")
        else:
            print("Nessuna regola scartata.")
        if rs.notes:
            print(f"\n{len(rs.notes)} regole adattate o con avvisi di sintassi (caricate comunque):")
            for label, msg in rs.notes:
                print(f"  - {label}: {msg}")
        return 0

    if not rs.rules:
        log.error("Nessuna regola caricata da %s", rules_dir)
        return 1
    _warn_if_no_gitleaks(rs, rules_dir, log)

    opts = AnalyzerOptions(
        only=args.only, min_severity=args.min_severity, skip_vendor=args.skip_vendor,
        include_node_modules=args.include_node_modules, normalize=not args.no_normalize,
        aggressive=args.aggressive, max_matches=max(1, args.max_matches), max_file_size=args.max_file_size,
        show_secrets=args.show_secrets, no_path_allowlist=args.no_path_allowlist,
    )
    inputs = args.inputs or ["js_downloads"]
    sites, loose = [], []
    for item in inputs:
        p = Path(item)
        if not p.exists():
            log.error("Percorso non trovato: %s", item)
            return 1
        found = discover_sites(p) if p.is_dir() else []
        if found:
            sites += found
        else:
            loose.append(item)
    for s in sites:
        analyze_site(s, rs, opts, log)
    if loose:
        out = Path(args.output_dir or "analysis_out")
        an = analyze_inputs(iter_loose_inputs(loose, opts), rs, opts, log)
        stats = write_outputs(out, an, "file sciolti", opts, rs)
        log.info("Analisi file sciolti: %d file, %d segreti, %d endpoint -> %s", stats["files_scanned"],
                 stats["secrets"], stats["endpoints"], out)
        print_summary(an, opts, log)
    return 0


if __name__ == "__main__":
    sys.exit(main())