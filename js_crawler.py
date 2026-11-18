#!/usr/bin/env python3
"""
JS Crawler v2 - Security Research Tool
======================================
Crawla siti web e scarica i file JavaScript (e le relative sourcemap) per
analisi di sicurezza. Da usare SOLO su target per cui hai un'autorizzazione.

Novita' rispetto alla v1:
  - input normalizzato: host senza schema, "*.dominio.it" come regola di scope
  - scope esplicito (--scope, --include-third-party): le terze parti finiscono
    nel manifest ma non vengono scaricate, salvo richiesta
  - ricerca di JS anche dentro ai JS (import, chunk webpack) e delle .js.map
  - stop per saturazione + campionamento per template di URL (niente piu'
    1000 pagine per trovare 14 file)
  - pagine in parallelo con rate limit per host, robots.txt per host e per URL
  - download in streaming con tetto di dimensione, scarto delle risposte HTML
  - file salvati per percorso (host/path), dedup per contenuto (SHA-256)
  - manifest JSONL scritto in modo incrementale + --resume
  - opzioni da pentest: --header, --cookie, --proxy, --insecure, --user-agent

Uso:
  python js_crawler.py -f sites.txt
  python js_crawler.py -s https://example.com --scope '*.example.com'
  cat hosts.txt | python js_crawler.py -f -
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import logging
import os
import re
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qsl, unquote, urldefrag, urlencode, urljoin, urlparse, urlunparse
from urllib.robotparser import RobotFileParser

import requests
import urllib3
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import lxml  # noqa: F401

    HTML_PARSER = "lxml"
except ImportError:  # lxml e' opzionale
    HTML_PARSER = "html.parser"

VERSION = "2.0"

DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
)
HTML_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

# Estensioni che non sono pagine HTML: non le seguiamo come link
SKIP_PAGE_EXT = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp", ".avif",
    ".css", ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".webm", ".avi", ".mov", ".wav",
    ".zip", ".rar", ".tar", ".gz", ".7z", ".exe", ".dmg", ".apk", ".iso",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".js", ".mjs", ".map", ".json", ".xml", ".txt", ".csv",
}
TRACKING_PARAMS = {"fbclid", "gclid", "msclkid", "dclid", "yclid", "_ga", "_gl", "mc_cid", "mc_eid"}

# Sorgenti "speculative": un 404 qui e' normale, non va segnalato come problema
QUIET_SOURCES = {"inline-ref", "js-ref", "webpack-chunk", "sourcemap"}
MAX_JS_CANDIDATES_PER_FILE = 200

# --- Regex per l'estrazione dei riferimenti JS -------------------------------
_UC = r"""[^"'\s|^<>\\`{}]"""  # caratteri ammessi in un URL dentro a una stringa
JS_STR_RE = re.compile(
    "".join(
        [
            r"""["'](""",
            r"""(?:https?:)?//""" + _UC + r"""+?\.m?js(?:\?""" + _UC + r"""*)?""",
            r"""|(?:\.{0,2}/)?[A-Za-z0-9_\-./%@~+]+?\.m?js(?:\?""" + _UC + r"""*)?""",
            r""")["']""",
        ]
    )
)
SOURCEMAP_RE = re.compile(r"[#@]\s*sourceMappingURL=([^\s'\"]+)")
WEBPACK_U_RE = re.compile(
    r"\.u\s*=\s*(?:function\s*\(\s*\w+\s*\)\s*\{\s*return\s*|\(?\s*\w+\s*\)?\s*=>\s*)"
)
WEBPACK_CHUNK_RE = re.compile(
    r"""^\s*(?:"(?P<pre>[^"]*)"\s*\+\s*)?(?P<id>\w+)\s*\+\s*"(?P<sep>[^"]*)"\s*\+\s*"""
    r"""\{(?P<map>[^{}]+)\}\s*\[\s*\w+\s*\]\s*\+\s*"(?P<suf>[^"]*\.m?js)\""""
)
WEBPACK_MAP_ITEM_RE = re.compile(r"""(?:(\w+)|"([^"]+)")\s*:\s*"([^"]*)\"""")
WEBPACK_P_RE = re.compile(r"""\.p\s*=\s*"([^"]*)\"""")


# =============================================================================
# Funzioni di utilita' per gli URL
# =============================================================================
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _is_ip(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host)) or ":" in host


def valid_http_url(url: str) -> bool:
    try:
        p = urlparse(url)
        return p.scheme in ("http", "https") and bool(p.hostname) and len(url) <= 2048
    except ValueError:
        return False


def strip_fragment(url: str) -> str:
    return urldefrag(url)[0]


def normalize_url(url: str) -> Optional[str]:
    """Forma canonica per la dedup delle PAGINE: niente fragment, host minuscolo,
    porta di default rimossa, parametri di tracking scartati, query ordinata."""
    try:
        p = urlparse(url)
        scheme = p.scheme.lower()
        host = (p.hostname or "").lower()
        port = p.port
    except ValueError:
        return None
    if scheme not in ("http", "https") or not host:
        return None
    if ":" in host:
        host = f"[{host}]"
    netloc = host
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    pairs = [
        (k, v)
        for k, v in parse_qsl(p.query, keep_blank_values=True)
        if not (k.lower().startswith("utm_") or k.lower() in TRACKING_PARAMS)
    ]
    query = urlencode(sorted(pairs))
    return urlunparse((scheme, netloc, p.path or "/", "", query, ""))


_UUID_RE = re.compile(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_HEX_RE = re.compile(r"(?i)[0-9a-f]{12,}")


def template_key(url: str) -> str:
    """Chiave di 'template' di una pagina: /prodotto/123 e /prodotto/456 coincidono."""
    p = urlparse(url)
    segs = []
    for s in p.path.split("/"):
        s = _UUID_RE.sub("{uuid}", s)
        s = _HEX_RE.sub("{h}", s)
        s = re.sub(r"\d+", "{n}", s)
        segs.append(s)
    names = sorted({k for k, _ in parse_qsl(p.query, keep_blank_values=True)})
    return f"{p.netloc}{'/'.join(segs)}?{','.join(names)}"


def _safe_segment(seg: str) -> str:
    seg = unquote(seg)
    seg = re.sub(r"[^A-Za-z0-9._\-@+~=,()]", "_", seg)
    if not seg.strip("."):
        return "_"
    if len(seg) > 120:
        base, ext = os.path.splitext(seg)
        seg = base[:100] + "__" + hashlib.sha1(seg.encode()).hexdigest()[:8] + ext[:10]
    return seg


def url_to_parts(url: str, kind: str) -> tuple[str, list[str]]:
    """URL -> (cartella host, segmenti del percorso). Preserva la struttura del sito;
    la query finisce in un hash breve cosi' ?v=1.0 e ?v=1.1 non collidono."""
    p = urlparse(url)
    host = (p.hostname or "unknown").lower()
    if p.port:
        host += f"_{p.port}"
    segs = [_safe_segment(s) for s in p.path.split("/") if s not in ("", ".", "..")]
    if not segs or p.path.endswith("/"):
        segs.append("index")
    name = segs[-1]
    is_js = os.path.splitext(name)[1].lower() in (".js", ".mjs")
    if p.query:
        qh = hashlib.sha1(p.query.encode()).hexdigest()[:8]
        if is_js:
            base, ext = os.path.splitext(name)
            name = f"{base}__{qh}{ext}"
        else:
            name = f"{name}__{qh}"
    if kind == "sourcemap":
        if not name.endswith(".map"):
            name += ".map"
    elif os.path.splitext(name)[1].lower() not in (".js", ".mjs"):
        name += ".js"
    segs[-1] = name
    return host, segs


# =============================================================================
# Input: righe di sites.txt
# =============================================================================
@dataclass
class Target:
    seed: str
    scope: list
    guessed_scheme: bool
    raw: str


def parse_site_line(line: str) -> Optional[Target]:
    """'www.sito.it' -> https://www.sito.it/ ; '*.sito.it' -> seed apex + scope wildcard."""
    line = re.split(r"\s+#", line.strip(), maxsplit=1)[0].strip()
    if not line or line.startswith("#"):
        return None
    raw = line
    wildcard = False
    if line.startswith("*."):
        wildcard = True
        line = line[2:]
    guessed = "://" not in line
    url = f"https://{line}" if guessed else line
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
    except ValueError:
        return None
    if not host or p.scheme not in ("http", "https"):
        return None
    scope = {host}
    if not _is_ip(host):
        scope.add(host[4:] if host.startswith("www.") else f"www.{host}")
    if wildcard:
        scope.add(f"*.{host}")
    seed = urlunparse((p.scheme, p.netloc, p.path or "/", "", p.query, ""))
    return Target(seed=seed, scope=sorted(scope), guessed_scheme=guessed, raw=raw)


def load_targets(path: str, log: logging.Logger) -> list[Target]:
    if path == "-":
        lines = sys.stdin.read().splitlines()
    else:
        if not os.path.exists(path):
            log.error("File non trovato: %s", path)
            return []
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    targets, seen = [], set()
    for raw in lines:
        t = parse_site_line(raw)
        stripped = raw.strip()
        if t is None:
            if stripped and not stripped.startswith("#"):
                log.warning("Riga ignorata (non valida): %r", stripped)
            continue
        if t.seed not in seen:
            seen.add(t.seed)
            targets.append(t)
    return targets


# =============================================================================
# Configurazione e stato
# =============================================================================
@dataclass
class Config:
    delay: float = 1.0
    workers: int = 3
    max_depth: int = 2
    max_pages: int = 1000
    per_template: int = 3
    stop_after_no_new: int = 50
    max_js_depth: int = 3
    max_file_size: int = 10 * 1024 * 1024
    max_page_size: int = 5 * 1024 * 1024
    timeout: float = 30.0
    respect_robots: bool = True
    include_third_party: bool = False
    sourcemaps: bool = True
    keep_suspicious: bool = False
    resume: bool = False
    extra_scope: list = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    cookie: Optional[str] = None
    proxy: Optional[str] = None
    insecure: bool = False
    user_agent: str = DEFAULT_UA


@dataclass
class Fetched:
    status: str  # ok | not_found | http_error | error | too_large | wrong_content_type | redirected_out_of_scope
    http_status: Optional[int] = None
    final_url: Optional[str] = None
    headers: dict = field(default_factory=dict)
    body: Optional[bytes] = None
    error: Optional[str] = None


class JsonlWriter:
    def __init__(self, path: Path, append: bool):
        self._f = open(path, "a" if append else "w", encoding="utf-8")
        self._lock = threading.Lock()

    def write(self, obj: dict) -> None:
        line = json.dumps(obj, ensure_ascii=False)
        with self._lock:
            self._f.write(line + "\n")
            self._f.flush()

    def close(self) -> None:
        with self._lock:
            self._f.close()


class SiteState:
    """Tutto lo stato di UN sito (cosi' non si mescola tra un sito e l'altro)."""

    def __init__(self, target: Target, site_dir: Path, scope: list, append: bool):
        self.target = target
        self.site_dir = site_dir
        self.scope = scope
        self.lock = threading.Lock()
        self.pages_seen: set = set()
        self.page_cache: dict = {}  # solo --resume: url -> link salvati
        self.template_counts: Counter = Counter()
        self.skipped_by_template: set = set()
        self.js_seen: set = set()
        self.hash_index: dict = {}  # sha256 -> saved_path
        self.paths_used: set = set()
        self.status_counts: Counter = Counter()
        self.pages_crawled = 0
        self.no_new_streak = 0
        self.bytes_saved = 0
        self.saturated = threading.Event()
        self.manifest = JsonlWriter(site_dir / "manifest.jsonl", append)
        self.pages = JsonlWriter(site_dir / "pages.jsonl", append)


class HostLimiter:
    """Intervallo minimo tra due richieste allo stesso host, valido tra tutti i thread."""

    def __init__(self, default_delay: float, stop: threading.Event):
        self.default = default_delay
        self.stop = stop
        self._next: dict = {}
        self._override: dict = {}
        self._lock = threading.Lock()

    def set_override(self, host: str, delay: float) -> None:
        with self._lock:
            self._override[host] = delay

    def wait(self, host: str) -> None:
        with self._lock:
            now = time.monotonic()
            interval = max(self.default, self._override.get(host, 0.0))
            slot = max(now, self._next.get(host, 0.0))
            self._next[host] = slot + interval
            sleep_for = slot - now
        if sleep_for > 0:
            self.stop.wait(sleep_for)


class RobotsCache:
    """robots.txt per origine (scaricato una volta) e controllato per OGNI URL."""

    def __init__(self, fetch, limiter: HostLimiter, log: logging.Logger, max_crawl_delay: float = 30.0):
        self._fetch = fetch
        self._limiter = limiter
        self._log = log
        self._max_cd = max_crawl_delay
        self._cache: dict = {}
        self._lock = threading.Lock()

    def _load(self, origin: str) -> RobotFileParser:
        rp = RobotFileParser()
        lines: list = []
        try:
            resp = self._fetch(origin + "/robots.txt")
            try:
                if resp.status_code == 200:
                    lines = resp.content[: 512 * 1024].decode("utf-8", "replace").splitlines()
                elif resp.status_code >= 500:
                    self._log.warning("robots.txt %s: HTTP %s, assumo tutto permesso", origin, resp.status_code)
                # 4xx = robots assente -> tutto permesso (RFC 9309)
            finally:
                resp.close()
        except requests.RequestException as e:
            self._log.warning("robots.txt %s non leggibile (%s), assumo tutto permesso", origin, e)
        rp.parse(lines)
        rp.modified()
        cd = rp.crawl_delay("*")
        if cd:
            cd = min(float(cd), self._max_cd)
            self._limiter.set_override(urlparse(origin).hostname or "", cd)
            self._log.info("robots.txt %s: Crawl-delay %.1fs", origin, cd)
        return rp

    def allowed(self, url: str) -> bool:
        p = urlparse(url)
        origin = f"{p.scheme}://{p.netloc}"
        with self._lock:
            rp = self._cache.get(origin)
            if rp is None:
                rp = self._cache[origin] = self._load(origin)
        return rp.can_fetch("*", url)


# =============================================================================
# Crawler
# =============================================================================
class JSCrawler:
    def __init__(self, cfg: Config, log: logging.Logger):
        self.cfg = cfg
        self.log = log
        self.stop = threading.Event()
        self.limiter = HostLimiter(cfg.delay, self.stop)
        self.session = self._build_session()
        self.auth_headers = dict(cfg.headers)
        if cfg.cookie:
            self.auth_headers["Cookie"] = cfg.cookie
        self.robots = RobotsCache(self._get, self.limiter, log)
        self.scope: list = []
        self.state: Optional[SiteState] = None

    # ----------------------------------------------------------------- HTTP
    def _build_session(self) -> requests.Session:
        s = requests.Session()
        retry = Retry(
            total=3,
            connect=2,
            read=2,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"],
            respect_retry_after_header=True,
            raise_on_status=False,  # a fine retry vogliamo la risposta, non un'eccezione
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=max(10, self.cfg.workers * 2))
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        s.headers.update(
            {
                "User-Agent": self.cfg.user_agent,
                "Accept": HTML_ACCEPT,
                "Accept-Language": "en-US,en;q=0.7,it;q=0.5",
            }
        )
        if self.cfg.proxy:
            s.proxies = {"http": self.cfg.proxy, "https": self.cfg.proxy}
        if self.cfg.insecure:
            s.verify = False
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        return s

    def in_scope(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        return any(fnmatch.fnmatchcase(host, pat) for pat in self.scope)

    def _get(self, url: str, referer: Optional[str] = None, accept: Optional[str] = None, max_redirects: int = 8):
        """GET in streaming con redirect gestiti a mano: cosi' cookie/header di
        autenticazione vanno solo agli host in scope, anche dopo un redirect."""
        current = url
        for _ in range(max_redirects + 1):
            self.limiter.wait(urlparse(current).hostname or "")
            headers = {}
            if accept:
                headers["Accept"] = accept
            if referer:
                headers["Referer"] = referer
            if self.in_scope(current):
                headers.update(self.auth_headers)
            resp = self.session.get(
                current, headers=headers, stream=True, timeout=(10, self.cfg.timeout), allow_redirects=False
            )
            if resp.is_redirect and resp.headers.get("location"):
                nxt = urljoin(current, resp.headers["location"])
                resp.close()
                if not valid_http_url(nxt):
                    raise requests.RequestException(f"redirect non valido: {nxt[:120]}")
                current = strip_fragment(nxt)
                continue
            return resp
        raise requests.TooManyRedirects(f"troppi redirect partendo da {url}")

    @staticmethod
    def _read_capped(resp, cap: int) -> Optional[bytes]:
        chunks, total = [], 0
        for chunk in resp.iter_content(65536):
            if not chunk:
                continue
            total += len(chunk)
            if total > cap:
                return None
            chunks.append(chunk)
        return b"".join(chunks)

    def _download(self, url, *, referer=None, accept=None, cap, ctype_any=None, allow_out_of_scope=False) -> Fetched:
        try:
            resp = self._get(url, referer=referer, accept=accept)
        except requests.RequestException as e:
            return Fetched("error", error=f"{type(e).__name__}: {e}"[:300])
        try:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            f = Fetched("ok", resp.status_code, resp.url, headers)
            if not allow_out_of_scope and not self.in_scope(resp.url):
                f.status = "redirected_out_of_scope"
                return f
            if resp.status_code in (404, 410):
                f.status = "not_found"
                return f
            if resp.status_code >= 300:
                f.status = "http_error"
                return f
            ctype = headers.get("content-type", "").lower()
            if ctype_any and ctype and not any(t in ctype for t in ctype_any):
                f.status = "wrong_content_type"
                return f
            cl = headers.get("content-length", "")
            if cl.isdigit() and int(cl) > cap:
                f.status = "too_large"
                return f
            body = self._read_capped(resp, cap)
            if body is None:
                f.status = "too_large"
                return f
            f.body = body
            return f
        except requests.RequestException as e:
            return Fetched("error", error=f"{type(e).__name__}: {e}"[:300])
        finally:
            resp.close()

    # ------------------------------------------------------------ estrazione
    def _parse_html(self, soup: BeautifulSoup, base: str):
        base_tag = soup.find("base", href=True)
        if base_tag:
            base = urljoin(base, base_tag["href"])
        js: dict = {}

        def add(ref: str, source: str) -> None:
            u = strip_fragment(urljoin(base, ref.strip()))
            if valid_http_url(u):
                js.setdefault(u, source)

        for s in soup.find_all("script", src=True):
            add(s["src"], "script-src")
        for link in soup.find_all("link", href=True):
            rel = " ".join(link.get("rel") or []).lower()
            as_ = (link.get("as") or "").lower()
            if "modulepreload" in rel or (("preload" in rel or "prefetch" in rel) and as_ == "script"):
                add(link["href"], "link-preload")
        for s in soup.find_all("script", src=False):
            stype = (s.get("type") or "").lower()
            if stype and not ("javascript" in stype or "module" in stype or stype == "text/babel"):
                continue  # JSON-LD, template, importmap...
            text = s.string or s.get_text()
            if text:
                for m in JS_STR_RE.finditer(text):
                    add(m.group(1), "inline-ref")

        links: dict = {}
        for tag in soup.find_all(["a", "area", "iframe", "frame"]):
            ref = tag.get("src") if tag.name in ("iframe", "frame") else tag.get("href")
            if not ref:
                continue
            n = normalize_url(urljoin(base, ref.strip()))
            if not n or len(n) > 2048 or not self.in_scope(n):
                continue
            if os.path.splitext(urlparse(n).path)[1].lower() in SKIP_PAGE_EXT:
                continue
            links[n] = None
        return list(js.items()), list(links)

    def _extract_from_js(self, text: str, js_url: str) -> list:
        """Riferimenti JS dentro a un file JS: stringhe-percorso e chunk webpack."""
        out: dict = {}
        count = 0
        for m in JS_STR_RE.finditer(text):
            ref = m.group(1)
            if not ref.startswith(("/", "./", "../", "http://", "https://")):
                continue  # niente nomi 'nudi': troppi falsi positivi
            u = strip_fragment(urljoin(js_url, ref))
            if valid_http_url(u) and u not in out:
                out[u] = "js-ref"
                count += 1
                if count >= MAX_JS_CANDIDATES_PER_FILE:
                    break

        # Webpack: __webpack_require__.u = e => "static/js/" + e + "." + {id:"hash"}[e] + ".chunk.js"
        pm = WEBPACK_P_RE.search(text)
        public_path = pm.group(1) if pm and pm.group(1) not in ("", "auto") else "/"
        base = urljoin(js_url, public_path)
        for m in WEBPACK_U_RE.finditer(text):
            cm = WEBPACK_CHUNK_RE.match(text[m.end(): m.end() + 20000])
            if not cm:
                continue
            pre, sep, suf = cm.group("pre") or "", cm.group("sep"), cm.group("suf")
            n = 0
            for im in WEBPACK_MAP_ITEM_RE.finditer(cm.group("map")):
                key = im.group(1) or im.group(2)
                u = strip_fragment(urljoin(base, f"{pre}{key}{sep}{im.group(3)}{suf}"))
                if valid_http_url(u) and u not in out:
                    out[u] = "webpack-chunk"
                    n += 1
                    if n >= 2000:
                        break
        return list(out.items())

    @staticmethod
    def _sourcemap_ref(text: str, headers: dict, js_url: str):
        ref = headers.get("sourcemap") or headers.get("x-sourcemap")
        if not ref:
            found = SOURCEMAP_RE.findall(text[-4096:])
            ref = found[-1] if found else None
        if not ref:
            return None, False
        if ref.startswith("data:"):
            return None, True  # sourcemap inline: niente da scaricare
        u = strip_fragment(urljoin(js_url, ref))
        return (u if valid_http_url(u) else None), False

    # --------------------------------------------------------------- manifest
    def _record(self, rec: dict) -> None:
        st = self.state
        with st.lock:
            st.status_counts[rec["status"]] += 1
        st.manifest.write(rec)

    def _choose_path(self, url: str, kind: str, suspicious: bool) -> str:
        """Percorso relativo a site_dir. DA CHIAMARE con st.lock tenuto."""
        st = self.state
        host, segs = url_to_parts(url, kind)
        rel = "/".join([("_suspicious" if suspicious else "js"), host] + segs)
        if rel in st.paths_used:
            base, ext = os.path.splitext(rel)
            rel = f"{base}__{hashlib.sha1(url.encode()).hexdigest()[:8]}{ext}"
            i = 1
            while rel in st.paths_used:
                rel = f"{base}__{hashlib.sha1(url.encode()).hexdigest()[:8]}_{i}{ext}"
                i += 1
        st.paths_used.add(rel)
        return rel

    def _write_file(self, rel: str, data: bytes) -> None:
        path = self.state.site_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".part")
        tmp.write_bytes(data)
        os.replace(tmp, path)

    # --------------------------------------------------------------- download JS
    def _fetch_js(self, url: str, referrer: str, source: str, js_depth: int) -> int:
        """Scarica un JS (o una sourcemap) e segue i suoi riferimenti.
        Ritorna il numero di file NUOVI salvati (contenuto mai visto prima)."""
        st, cfg = self.state, self.cfg
        if self.stop.is_set():
            return 0
        key = strip_fragment(url)
        kind = "sourcemap" if source == "sourcemap" else "js"
        quiet = source in QUIET_SOURCES
        with st.lock:
            if key in st.js_seen:
                return 0
            st.js_seen.add(key)

        rec = {"url": key, "referrer": referrer, "source": source, "js_depth": js_depth, "time": now_iso()}
        rec["in_scope"] = self.in_scope(key)
        if not rec["in_scope"] and not cfg.include_third_party:
            rec["status"] = "skipped_out_of_scope"
            self._record(rec)
            self.log.debug("fuori scope, non scaricato: %s", key)
            return 0

        cap = cfg.max_file_size * (5 if kind == "sourcemap" else 1)
        f = self._download(key, referer=referrer, accept="*/*", cap=cap, allow_out_of_scope=cfg.include_third_party)
        rec.update(
            status=f.status,
            http_status=f.http_status,
            final_url=f.final_url,
            content_type=f.headers.get("content-type"),
            etag=f.headers.get("etag"),
            last_modified=f.headers.get("last-modified"),
        )
        if f.error:
            rec["error"] = f.error

        if f.status != "ok":
            level = logging.DEBUG if (quiet and f.status == "not_found") else logging.WARNING
            self.log.log(level, "JS %s: %s %s", f.status, key, f.error or f.http_status or "")
            self._record(rec)
            return 0

        body = f.body or b""
        if not body:
            rec["status"] = "empty"
            self._record(rec)
            return 0

        ctype = (f.headers.get("content-type") or "").lower()
        head = body.lstrip()[:15].lower()
        suspicious = "html" in ctype or head.startswith((b"<!doctype", b"<html", b"<head", b"<?xml"))
        if suspicious and not cfg.keep_suspicious:
            rec["status"] = "rejected_html"
            self.log.log(logging.DEBUG if quiet else logging.WARNING, "JS scartato (sembra HTML, %s): %s", ctype or "?", key)
            self._record(rec)
            return 0

        digest = hashlib.sha256(body).hexdigest()
        rec["size"], rec["sha256"] = len(body), digest
        dup_of = None
        with st.lock:
            if not suspicious and digest in st.hash_index:
                dup_of = st.hash_index[digest]
            else:
                rel = self._choose_path(f.final_url or key, kind, suspicious)  # nome dal file realmente servito
                if not suspicious:
                    st.hash_index[digest] = rel
        if dup_of:
            rec.update(status="duplicate", duplicate_of=dup_of, saved_path=dup_of)
            self.log.debug("duplicato di %s: %s", dup_of, key)
            self._record(rec)
            new_files = 0
        else:
            try:
                self._write_file(rel, body)
            except OSError as e:
                with st.lock:
                    st.hash_index.pop(digest, None)
                rec.update(status="error", error=f"scrittura fallita: {e}")
                self.log.error("scrittura fallita %s: %s", rel, e)
                self._record(rec)
                return 0
            with st.lock:
                st.bytes_saved += len(body)
            rec.update(status="ok", saved_path=rel)
            if suspicious:
                rec["status"] = "suspicious_saved"
            self.log.info("JS [%s] %s -> %s (%d B)", source, key, rel, len(body))
            self._record(rec)
            new_files = 1

        if kind == "js" and not suspicious:
            text = body.decode("utf-8", "replace")
            new_files += self._follow(text, f.headers, f.final_url or key, key, js_depth)
        return new_files

    def _follow(self, text: str, headers: dict, final_url: str, key: str, js_depth: int) -> int:
        """Dal contenuto di un JS: altri JS (chunk, import) e sourcemap."""
        n = 0
        if js_depth < self.cfg.max_js_depth:
            for child, src in self._extract_from_js(text, final_url):
                n += self._fetch_js(child, referrer=key, source=src, js_depth=js_depth + 1)
        if self.cfg.sourcemaps:
            map_url, inline = self._sourcemap_ref(text, headers, final_url)
            if map_url:
                n += self._fetch_js(map_url, referrer=key, source="sourcemap", js_depth=js_depth)
            elif inline:
                self.log.info("sourcemap inline in %s (non estratta)", key)
        return n

    # --------------------------------------------------------------- pagine
    def _select(self, frontier: list, depth: int) -> list:
        """Sceglie le pagine da visitare: dedup, tetto globale, campionamento per template."""
        st, cfg = self.state, self.cfg
        out = []
        for u in frontier:
            n = normalize_url(u)
            if not n:
                continue
            with st.lock:
                if len(st.pages_seen) >= cfg.max_pages:
                    break
                if n in st.pages_seen:
                    continue
                tk = template_key(n)
                if depth > 0 and st.template_counts[tk] >= cfg.per_template:
                    st.skipped_by_template.add(n)
                    continue
                st.template_counts[tk] += 1
                st.pages_seen.add(n)
            out.append(n)
        return out

    def _process_page(self, url: str, depth: int) -> list:
        st, cfg = self.state, self.cfg
        if self.stop.is_set() or st.saturated.is_set():
            return []
        cached = st.page_cache.get(url)
        if cached is not None:
            self.log.debug("pagina gia' vista (resume): %s", url)
            return cached

        if cfg.respect_robots and not self.robots.allowed(url):
            self.log.info("bloccato da robots.txt: %s", url)
            st.pages.write({"url": url, "depth": depth, "status": "robots_blocked", "links": []})
            return []

        self.log.info("pagina (depth %d): %s", depth, url)
        f = self._download(url, accept=HTML_ACCEPT, cap=cfg.max_page_size, ctype_any=("html", "xml"))
        rec = {"url": url, "final_url": f.final_url, "depth": depth, "status": f.status, "http_status": f.http_status, "time": now_iso()}
        if f.status != "ok":
            if f.status == "error":
                rec["error"] = f.error
                self.log.warning("errore su %s: %s", url, f.error)
            st.pages.write({**rec, "links": []})
            return []

        final = f.final_url or url
        with st.lock:
            fn = normalize_url(final)
            if fn:
                st.pages_seen.add(fn)
        soup = BeautifulSoup(f.body, HTML_PARSER)
        js_refs, links = self._parse_html(soup, final)

        new_count = 0
        for js_url, source in js_refs:
            new_count += self._fetch_js(js_url, referrer=final, source=source, js_depth=0)

        rec.update(js_found=len(js_refs), js_new=new_count)
        st.pages.write({**rec, "links": links})
        with st.lock:
            st.pages_crawled += 1
            st.no_new_streak = 0 if new_count else st.no_new_streak + 1
            if cfg.stop_after_no_new and st.no_new_streak >= cfg.stop_after_no_new and not st.saturated.is_set():
                st.saturated.set()
                self.log.info(
                    "Saturazione: %d pagine consecutive senza JS nuovi, fermo il crawl delle pagine.",
                    st.no_new_streak,
                )
        return links

    # ----------------------------------------------------------------- sito
    def _resolve_scheme(self, target: Target) -> str:
        """Per le righe senza schema prova https e, se non risponde, http."""
        p = urlparse(target.seed)
        for scheme in ("https", "http"):
            cand = urlunparse((scheme, p.netloc, p.path, "", p.query, ""))
            try:
                self.limiter.wait(p.hostname or "")
                r = self.session.get(cand, stream=True, timeout=(8, 10), allow_redirects=False)
                r.close()
                return cand
            except requests.RequestException as e:
                self.log.debug("%s non raggiungibile: %s", cand, e)
        self.log.warning("%s non raggiungibile ne' in https ne' in http, riprovo comunque in https", p.netloc)
        return target.seed

    def _load_resume(self) -> list:
        """Ricarica manifest e pagine di un run precedente. Ritorna i JS da ri-analizzare."""
        st, cfg = self.state, self.cfg
        reprocess = []
        mp = st.site_dir / "manifest.jsonl"
        pp = st.site_dir / "pages.jsonl"
        if mp.exists():
            for line in mp.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if not rec.get("url") or rec.get("status") == "error":
                    continue  # gli errori vengono ritentati
                st.js_seen.add(rec["url"])
                st.status_counts[rec["status"]] += 1
                if rec["status"] == "ok" and rec.get("saved_path") and rec.get("sha256"):
                    st.hash_index[rec["sha256"]] = rec["saved_path"]
                    st.paths_used.add(rec["saved_path"])
                    st.bytes_saved += rec.get("size", 0)
                    if rec.get("source") != "sourcemap":
                        reprocess.append(rec)
        if pp.exists():
            for line in pp.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if rec.get("status") in ("ok", "wrong_content_type", "not_found", "http_error", "robots_blocked") and rec.get("url"):
                    st.page_cache[rec["url"]] = rec.get("links", [])
        self.log.info("Resume: %d URL JS e %d pagine gia' note", len(st.js_seen), len(st.page_cache))
        return reprocess

    def crawl_target(self, target: Target, output_dir: Path) -> dict:
        cfg = self.cfg
        seed = self._resolve_scheme(target) if target.guessed_scheme else target.seed
        site_name = re.sub(r"[^A-Za-z0-9._-]", "_", urlparse(seed).netloc)
        site_dir = Path(output_dir) / site_name
        (site_dir / "js").mkdir(parents=True, exist_ok=True)

        scope = list(dict.fromkeys(target.scope + [s.lower() for s in cfg.extra_scope]))
        self.scope = scope
        self.state = st = SiteState(target, site_dir, scope, append=cfg.resume)
        self.log.info("=== %s | scope: %s", seed, ", ".join(scope))

        started = now_iso()
        t0 = time.monotonic()
        try:
            if cfg.resume:
                for rec in self._load_resume():
                    path = site_dir / rec["saved_path"]
                    try:
                        text = path.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        continue
                    self._follow(text, {}, rec.get("final_url") or rec["url"], rec["url"], rec.get("js_depth", 0))

            frontier = [seed]
            for depth in range(cfg.max_depth + 1):
                if self.stop.is_set() or st.saturated.is_set() or not frontier:
                    break
                batch = self._select(frontier, depth)
                if not batch:
                    break
                self.log.info("Depth %d: %d pagine da processare", depth, len(batch))
                next_frontier: list = []
                ex = ThreadPoolExecutor(max_workers=cfg.workers)
                try:
                    futures = [ex.submit(self._process_page, u, depth) for u in batch]
                    for fut in as_completed(futures):
                        try:
                            next_frontier.extend(fut.result())
                        except Exception:  # un thread che fallisce non deve fermare il crawl
                            self.log.exception("errore inatteso in una pagina")
                except KeyboardInterrupt:
                    self.stop.set()
                    ex.shutdown(wait=False, cancel_futures=True)
                    raise
                ex.shutdown(wait=True)
                frontier = list(dict.fromkeys(next_frontier))
        finally:
            summary = self._write_summary(seed, started, time.monotonic() - t0)
            st.manifest.close()
            st.pages.close()
        return summary

    def _write_summary(self, seed: str, started: str, duration: float) -> dict:
        st, cfg = self.state, self.cfg
        saved = st.status_counts.get("ok", 0) + st.status_counts.get("suspicious_saved", 0)
        summary = {
            "tool": f"js_crawler {VERSION}",
            "site": seed,
            "site_dir": str(st.site_dir),
            "scope": st.scope,
            "started": started,
            "finished": now_iso(),
            "duration_seconds": round(duration, 1),
            "pages_crawled": st.pages_crawled,
            "pages_skipped_by_template": len(st.skipped_by_template),
            "stopped_by_saturation": st.saturated.is_set(),
            "interrupted": self.stop.is_set(),
            "files_saved": saved,
            "bytes_saved": st.bytes_saved,
            "status_counts": dict(st.status_counts),
            "settings": {
                "max_depth": cfg.max_depth,
                "max_pages": cfg.max_pages,
                "per_template": cfg.per_template,
                "stop_after_no_new": cfg.stop_after_no_new,
                "max_js_depth": cfg.max_js_depth,
                "delay": cfg.delay,
                "workers": cfg.workers,
                "robots": cfg.respect_robots,
                "include_third_party": cfg.include_third_party,
                "sourcemaps": cfg.sourcemaps,
                "custom_header_names": sorted(cfg.headers),
                "cookie_set": bool(cfg.cookie),
            },
        }
        with open(st.site_dir / "crawl_metadata.json", "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        self.log.info(
            "Fine %s: %d pagine, %d file salvati (%d B), %.0fs | %s",
            seed, st.pages_crawled, saved, st.bytes_saved, duration, dict(st.status_counts),
        )
        return summary


# =============================================================================
# CLI
# =============================================================================
def setup_logging(output_dir: Path, verbose: bool, quiet: bool) -> logging.Logger:
    log = logging.getLogger("jscrawler")
    log.setLevel(logging.DEBUG)
    log.handlers.clear()
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if verbose else logging.WARNING if quiet else logging.INFO)
    console.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%H:%M:%S"))
    log.addHandler(console)
    logs_dir = Path(output_dir) / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(logs_dir / f"crawl_{datetime.now():%Y%m%d_%H%M%S}.log", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s"))
    log.addHandler(fh)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    return log


def parse_header(value: str) -> tuple[str, str]:
    if ":" not in value:
        raise argparse.ArgumentTypeError(f"header non valido (atteso 'Nome: valore'): {value!r}")
    k, v = value.split(":", 1)
    return k.strip(), v.strip()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="JS Crawler v2 - scarica i file JavaScript (e le sourcemap) per analisi di sicurezza. "
        "Usalo solo su target autorizzati."
    )
    src = p.add_argument_group("input/output")
    src.add_argument("--sites-file", "-f", default="sites.txt", help="file con la lista siti; '-' = stdin (default: sites.txt)")
    src.add_argument("--single-site", "-s", help="crawla un singolo sito invece che da file")
    src.add_argument("--output-dir", "-o", default="js_downloads", help="cartella di output (default: js_downloads)")

    scope = p.add_argument_group("scope")
    scope.add_argument("--scope", action="append", default=[], metavar="GLOB", help="host/glob in scope in piu' (ripetibile, es. '*.example.com')")
    scope.add_argument("--include-third-party", action="store_true", help="scarica anche i JS fuori scope (default: solo nel manifest)")

    crawl = p.add_argument_group("crawl")
    crawl.add_argument("--max-depth", "-d", type=int, default=2, help="profondita' massima (default: 2)")
    crawl.add_argument("--max-pages", type=int, default=1000, help="massimo pagine per sito (default: 1000)")
    crawl.add_argument("--per-template", type=int, default=3, help="max pagine per template di URL, es. /prodotto/{n} (default: 3)")
    crawl.add_argument("--stop-after-no-new", type=int, default=50, help="stop dopo N pagine senza JS nuovi, 0 = mai (default: 50)")
    crawl.add_argument("--max-js-depth", type=int, default=3, help="quanti livelli seguire JS -> JS (default: 3)")
    crawl.add_argument("--no-sourcemaps", action="store_true", help="non cercare/scaricare le .map")
    crawl.add_argument("--no-robots", action="store_true", help="ignora robots.txt")
    crawl.add_argument("--resume", action="store_true", help="riprendi un run interrotto (usa manifest.jsonl/pages.jsonl)")

    net = p.add_argument_group("rete")
    net.add_argument("--delay", type=float, default=1.0, help="intervallo minimo tra richieste allo stesso host, in secondi (default: 1.0)")
    net.add_argument("--workers", "--max-workers", dest="workers", type=int, default=3, help="pagine in parallelo (default: 3)")
    net.add_argument("--max-file-size", type=int, default=10 * 1024 * 1024, help="dimensione massima di un JS in byte (default: 10MB)")
    net.add_argument("--timeout", type=float, default=30.0, help="timeout di lettura in secondi (default: 30)")
    net.add_argument("--header", "-H", action="append", default=[], type=parse_header, metavar="'Nome: valore'", help="header custom (ripetibile); inviati solo agli host in scope")
    net.add_argument("--cookie", help="header Cookie; inviato solo agli host in scope")
    net.add_argument("--proxy", help="proxy http(s), es. http://127.0.0.1:8080 (Burp)")
    net.add_argument("--insecure", action="store_true", help="non verificare i certificati TLS")
    net.add_argument("--user-agent", default=DEFAULT_UA, help="User-Agent")

    ana = p.add_argument_group("analisi")
    ana.add_argument("--analyze", action="store_true", help="a fine crawl analizza i JS con js_analyzer.py (segreti ed endpoint)")
    ana.add_argument("--rules-dir", help="cartella delle regole per l'analisi (default: rules/ accanto a js_analyzer.py)")

    p.add_argument("--keep-suspicious", action="store_true", help="salva in _suspicious/ le risposte che sembrano HTML invece di scartarle")
    p.add_argument("-v", "--verbose", action="store_true", help="log di debug sulla console")
    p.add_argument("-q", "--quiet", action="store_true", help="solo warning ed errori sulla console")
    return p


def run_analysis(summary: dict, rules_dir, log: logging.Logger) -> None:
    """Passa i file scaricati a js_analyzer.py (deve stare nella stessa cartella)."""
    try:
        import js_analyzer
    except ImportError:
        log.error("--analyze richiede js_analyzer.py nella stessa cartella di js_crawler.py")
        return
    try:
        js_analyzer.analyze_from_crawler(Path(summary["site_dir"]), rules_dir, log)
    except Exception:  # l'analisi non deve far perdere il crawl
        log.exception("Errore durante l'analisi (i file scaricati sono intatti: rilancia js_analyzer.py)")


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    output_dir = Path(args.output_dir)
    log = setup_logging(output_dir, args.verbose, args.quiet)

    cfg = Config(
        delay=max(0.0, args.delay),
        workers=max(1, args.workers),
        max_depth=max(0, args.max_depth),
        max_pages=max(1, args.max_pages),
        per_template=max(1, args.per_template),
        stop_after_no_new=max(0, args.stop_after_no_new),
        max_js_depth=max(0, args.max_js_depth),
        max_file_size=args.max_file_size,
        timeout=args.timeout,
        respect_robots=not args.no_robots,
        include_third_party=args.include_third_party,
        sourcemaps=not args.no_sourcemaps,
        keep_suspicious=args.keep_suspicious,
        resume=args.resume,
        extra_scope=args.scope,
        headers=dict(args.header),
        cookie=args.cookie,
        proxy=args.proxy,
        insecure=args.insecure,
        user_agent=args.user_agent,
    )

    if args.single_site:
        t = parse_site_line(args.single_site)
        targets = [t] if t else []
        if not t:
            log.error("Sito non valido: %r", args.single_site)
    else:
        targets = load_targets(args.sites_file, log)
    if not targets:
        log.error("Nessun target da crawlare.")
        return 1

    if cfg.headers:
        log.info("Header custom attivi (solo host in scope): %s", ", ".join(sorted(cfg.headers)))
    log.info("%d target da crawlare | output: %s | parser HTML: %s", len(targets), output_dir, HTML_PARSER)

    crawler = JSCrawler(cfg, log)
    try:
        for i, target in enumerate(targets, 1):
            log.info("Target %d/%d: %s", i, len(targets), target.raw)
            try:
                summary = crawler.crawl_target(target, output_dir)
                if args.analyze:
                    run_analysis(summary, args.rules_dir, log)
            except KeyboardInterrupt:
                raise
            except Exception:
                log.exception("Errore su %s, passo al prossimo", target.raw)
            if i < len(targets):
                crawler.stop.wait(cfg.delay)
    except KeyboardInterrupt:
        crawler.stop.set()
        log.warning("Interrotto dall'utente. Per riprendere: aggiungi --resume.")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())