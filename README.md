# JS Crawler + JS Analyzer

Due script Python per la ricognizione di siti web **autorizzati**:

- **`js_crawler.py`** crawla un sito e scarica i suoi file JavaScript (e le `.js.map`).
- **`js_analyzer.py`** analizza i file scaricati con regex e cerca **segreti** (chiavi API, token, chiavi private, JWT) ed **endpoint** (chiamate HTTP, percorsi API, host interni, bucket cloud, GraphQL).

> Usali solo su target per cui hai un'autorizzazione scritta. I risultati possono contenere
> segreti reali del cliente: trattali come dati sensibili.

## Quick start

Servono Python 3.9+ (3.11+ consigliato) e `python3-venv` (su Debian/Parrot/Kali: `sudo apt install python3-venv`).

```bash
bash SetUp.sh                    # crea il venv, installa le dipendenze, scarica rules/gitleaks.toml
source venv/bin/activate
nano sites.txt                   # i tuoi target autorizzati
python js_crawler.py -f sites.txt --analyze
```

Al termine trovi tutto in `js_downloads/<sito>/` (vedi [Output](#output)). Per provare l'analisi
su file già scaricati: `python js_analyzer.py js_downloads`.

## File del progetto

| File | A cosa serve |
|---|---|
| `js_crawler.py` | crawler e downloader |
| `js_analyzer.py` | analisi regex di segreti ed endpoint |
| `rules/extra_secrets.toml` | regole incluse per i segreti |
| `rules/endpoints.toml` | regole incluse per endpoint, URL, bucket, GraphQL |
| `rules/overrides.toml` | correzioni di severità/confidenza per id di regola |
| `rules/gitleaks.toml` | **non incluso**: lo scarica `SetUp.sh` (vedi [Regole](#regole)) |
| `SetUp.sh`, `requirements.txt` | installazione |

## Crawler

### Formato di `sites.txt`

Un target per riga, `#` per i commenti:

```text
https://www.example.com          # URL completo
www.example.com                  # senza schema: prova https, poi http
*.example.com                    # wildcard: parte da example.com e mette *.example.com nello scope
```

Si può leggere anche da stdin (`cat hosts.txt | python js_crawler.py -f -`) o crawlare un solo sito
con `-s https://example.com`.

### Come funziona

1. **Scope.** Per default sono in scope l'host del target e la variante con/senza `www`. Con
   `--scope '*.example.com'` (ripetibile) allarghi il perimetro. I JS fuori scope **non vengono
   scaricati**: finiscono nel manifest come `skipped_out_of_scope`. `--include-third-party` li scarica.
2. **Pagine.** Crawl a livelli fino a `--max-depth`, con pagine in parallelo (`--workers`) e un
   intervallo minimo per host (`--delay`). `robots.txt` è controllato per ogni URL (e il suo
   `Crawl-delay` rispettato) a meno di `--no-robots`.
3. **Meno pagine inutili.**
   - **Template:** al massimo `--per-template` pagine per forma di URL (`/prodotto/{n}`).
   - **Saturazione:** il crawl si ferma dopo `--stop-after-no-new` pagine consecutive senza JS nuovi.
   - **Normalizzazione:** fragment e parametri di tracking vengono ignorati.
4. **Dove cerca i JS.** `<script src>`, `<link rel=modulepreload|preload as=script>`, riferimenti
   negli script inline, `<base href>`. Dentro ai JS scaricati segue `import()`, altri percorsi e i
   chunk di webpack (fino a `--max-js-depth` livelli) e le `.js.map` (si disattiva con `--no-sourcemaps`).
5. **Download.** In streaming con tetto di dimensione (`--max-file-size`). Le risposte che sembrano
   HTML (pagine di errore servite come `.js`) vengono scartate (`rejected_html`); con
   `--keep-suspicious` si salvano in `_suspicious/`. Contenuti identici vengono salvati una volta
   sola (SHA-256).
6. **Interruzione.** Con Ctrl-C il manifest è già scritto; riparti con `--resume`.

### Opzioni

| Opzione | Default | Descrizione |
|---|---|---|
| `-f, --sites-file` | `sites.txt` | file dei target (`-` = stdin) |
| `-s, --single-site` | | crawla un solo sito |
| `-o, --output-dir` | `js_downloads` | cartella di output |
| `--scope GLOB` | | host in scope in più (ripetibile) |
| `--include-third-party` | off | scarica anche i JS fuori scope |
| `-d, --max-depth` | 2 | profondità di crawl |
| `--max-pages` | 1000 | massimo pagine per sito |
| `--per-template` | 3 | massimo pagine per template di URL |
| `--stop-after-no-new` | 50 | stop dopo N pagine senza JS nuovi (0 = mai) |
| `--max-js-depth` | 3 | livelli JS → JS |
| `--no-sourcemaps` | | non cercare le `.map` |
| `--no-robots` | | ignora `robots.txt` |
| `--resume` | | riprendi un run interrotto |
| `--delay` | 1.0 | secondi minimi tra richieste allo stesso host |
| `--workers` | 3 | pagine in parallelo |
| `--max-file-size` | 10 MB | dimensione massima di un JS |
| `--timeout` | 30 | timeout di lettura (s) |
| `-H, --header 'Nome: valore'` | | header custom (ripetibile) |
| `--cookie` | | header Cookie |
| `--proxy` | | es. `http://127.0.0.1:8080` (Burp) |
| `--insecure` | | non verificare i certificati TLS |
| `--user-agent` | Chrome recente | User-Agent |
| `--keep-suspicious` | | salva in `_suspicious/` le risposte che sembrano HTML |
| `--analyze` | | a fine crawl lancia `js_analyzer.py` |
| `--rules-dir` | `rules/` | cartella regole per `--analyze` |
| `-v, --verbose` / `-q, --quiet` | | verbosità della console |

`--header` e `--cookie` vengono inviati **solo agli host in scope**, anche dopo un redirect.

Esempi:

```bash
python js_crawler.py -s https://example.com --scope '*.example.com' -d 2
python js_crawler.py -f sites.txt --proxy http://127.0.0.1:8080 --insecure -H 'X-Pentest: nome'
python js_crawler.py -f sites.txt --delay 0.3 --workers 5      # più veloce
python js_crawler.py -f sites.txt --resume                      # dopo un'interruzione
```

## Output

```text
js_downloads/
├── logs/crawl_<data>.log          # un log per ogni run
└── <host>/
    ├── js/<host>/<percorso>.js    # i file, con la struttura del sito (?query -> __<hash>)
    ├── _suspicious/               # solo con --keep-suspicious
    ├── manifest.jsonl             # un record per ogni URL JS incontrato
    ├── pages.jsonl                # pagine visitate e link trovati (serve a --resume)
    ├── crawl_metadata.json        # riepilogo del crawl
    └── analysis/                  # prodotto da js_analyzer
```

Ogni record di `manifest.jsonl` ha: `url`, `final_url`, `referrer`, `source` (`script-src`,
`link-preload`, `inline-ref`, `js-ref`, `webpack-chunk`, `sourcemap`), `js_depth`, `in_scope`,
`status`, `http_status`, `content_type`, `etag`, `last_modified`, `size`, `sha256`, `saved_path`.
Gli `status` possibili: `ok`, `duplicate`, `not_found`, `http_error`, `error`, `too_large`,
`rejected_html`, `suspicious_saved`, `empty`, `skipped_out_of_scope`, `redirected_out_of_scope`.

## Analyzer

```bash
python js_analyzer.py js_downloads              # tutti i siti con manifest.jsonl
python js_analyzer.py js_downloads/www.example.com
python js_analyzer.py app.js bundle.js.map      # file sciolti (output in analysis_out/)
python js_analyzer.py --check-rules             # verifica le regole caricate
```

Cosa analizza: i file `ok` del manifest (i duplicati sono già saltati) e, per ogni `.js.map`, i
**sorgenti originali** nel campo `sourcesContent` (saltando `node_modules`). Prima di cercare
ricostruisce l'offuscamento banale: stringhe concatenate (`"AKI"+"A..."`), escape `\x41`/`\u0041`,
`atob("...")`.

### Filtri anti falsi positivi

- **Entropia** minima (per le regole che la prevedono), **placeholder** (`YOUR_API_KEY`, `example`, `xxxx`...) e valori con 1–2 caratteri distinti vengono scartati.
- **Allowlist** (globali e per regola, come in gitleaks): `regexes`, `stopwords`, `paths`, `regexTarget`, `condition`.
- **Validatori:** i JWT vengono decodificati; un falso JWT è scartato, `alg: none` sale a severità alta, un token scaduto scende a bassa.
- **Vendor e terze parti:** i match in librerie note (jQuery, bootstrap...) o in JS fuori scope hanno la confidenza abbassata di un livello; `--skip-vendor` li salta del tutto.
- **Chiavi pubbliche per design** (Google API key, Stripe `pk_live_`): severità `info` con una nota (`rules/overrides.toml`).
- **Duplicati:** lo stesso valore trovato da più regole o in più file diventa un solo finding con `occurrences` e `locations`.

### Opzioni

| Opzione | Descrizione |
|---|---|
| `--rules-dir DIR` | cartella con i file `.toml` (default: `rules/` accanto allo script) |
| `--only secrets\|endpoints` | analizza solo una delle due famiglie |
| `--min-severity info\|low\|medium\|high\|critical` | mostra/salva solo da questa severità in su |
| `--skip-vendor` | salta librerie vendor e JS di terze parti |
| `--include-node-modules` | analizza anche i `node_modules` delle sourcemap |
| `--aggressive` | abilita le regole rumorose (`aggressive = true`, es. `path-generic`) |
| `--no-normalize` | non ricostruire concatenazioni/escape/`atob` |
| `--max-matches N` | massimo match per regola per file (default 200) |
| `--max-file-size B` | salta i file più grandi |
| `--show-secrets` | valori in chiaro anche in console |
| `--no-path-allowlist` | ignora le allowlist per percorso |
| `-o, --output-dir` | cartella di output per i file sciolti |
| `--check-rules` | carica le regole, elenca scartate/adattate ed esce |

### Output (`analysis/`)

- **`findings.jsonl`** – segreti, **valori completi** (permessi `600`). Campi: `rule_id`, `rules`, `description`, `severity`, `confidence`, `secret`, `secret_masked`, `entropy`, `note`, `details`, `snippet`, `third_party`, `vendor`, `occurrences`, `locations[{file, url, line, col, variant}]` (`variant`: `original`, `normalized`, `atob`).
- **`endpoints.jsonl`** – endpoint con `value`, `methods`, `full_url`, `host`, `kind`, `tags`, `severity`, `rules`, `occurrences`, `sources`.
- **`endpoints.txt`** – elenco deduplicato e ordinato (URL completi dove risolvibili), pronto per ffuf, nuclei o Burp.
- **`report.md`** – riepilogo leggibile con i valori mascherati.

I tag degli endpoint: `admin`, `auth`, `debug`, `graphql`, `internal`, `payment`, `upload`, `user`.
In console i segreti sono sempre mascherati (primi e ultimi 4 caratteri) salvo `--show-secrets`.

## Regole

Le regole stanno in `rules/*.toml`, nello stesso formato di gitleaks. Vengono caricate tutte
(tranne `overrides.toml`) con `gitleaks.toml` per primo: **a parità di `id` vince il file caricato dopo**,
quindi le tue regole sostituiscono quelle di gitleaks.

### Regole di gitleaks

```bash
curl -L -o rules/gitleaks.toml https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
python js_analyzer.py --check-rules
```

`--check-rules` mostra quante regole sono state caricate, quali sono state scartate perché Python non
le compila (`\p{L}`, ecc.: `pip install regex` ne recupera la maggior parte) e quali sono state
adattate (le classi POSIX come `[[:alnum:]]` vengono tradotte). Il file è sotto licenza MIT: se lo
ridistribuisci, conserva l'avviso di copyright.

### Scrivere una regola

```toml
[[rules]]
id = "mia-chiave"
description = "Chiave interna del servizio X"
regex = '''\b(svcx_[A-Za-z0-9]{32})\b'''
secretGroup = 1                 # gruppo di cattura che contiene il segreto
keywords = ["svcx_"]            # pre-filtro veloce: la regola gira solo se compare una keyword
entropy = 3.0                   # opzionale: entropia minima del segreto
severity = "high"               # info | low | medium | high | critical
confidence = "high"             # low | medium | high
[[rules.allowlists]]
stopwords = ["test"]
```

Campi in più rispetto a gitleaks: `severity`, `confidence`, `validator` (`"jwt"`), `aggressive`,
`kind` (`secret` | `endpoint` | `url` | `infra` | `graphql`), `category`, `window_method`,
`exclude_hosts`. Per gli endpoint la regex usa i gruppi nominati `(?P<url>…)`, `(?P<method>…)` e
`(?P<fn>…)`. Nelle stringhe `'''…'''` scrivi gli apici singoli come `\x27`.

Per cambiare severità, confidenza o nota di una regola esistente senza toccarla, usa `rules/overrides.toml`:

```toml
[overrides.generic-api-key]
confidence = "low"
note = "Spesso rumore: verifica a mano."
```

## Limiti

- **Solo HTML statico:** il crawler non esegue JavaScript. Le pagine generate lato client mostrano solo i bundle referenziati nell'HTML iniziale (più i chunk che si riesce a dedurre).
- **Chunk webpack:** la ricostruzione funziona per il caso comune (`__webpack_require__.u` con mappa id→hash), non per tutte le varianti (es. Next.js).
- **Endpoint dinamici:** `"/api/"+a+"/items"` viene troncato al primo pezzo letterale.
- **Offuscamento:** solo concatenazioni, escape e `atob`; niente deoffuscamento vero.
- **Regex:** `re` di Python non ha timeout. Su bundle enormi una regola di gitleaks può rallentare: abbassa `--max-matches` o `--max-file-size`.
- **Nessuna verifica attiva:** le chiavi trovate non vengono provate contro i servizi reali.
- **Chiavi pubbliche:** una chiave Google/Firebase trovata non è automaticamente una vulnerabilità: controlla le restrizioni prima di segnalarla.

## Risoluzione dei problemi

| Sintomo | Causa / rimedio |
|---|---|
| `SetUp.sh` si ferma su `venv` | `sudo apt install python3-venv` |
| `rules/gitleaks.toml non trovato` | scaricalo con il comando curl sopra |
| 0 segreti trovati | normale su librerie pubbliche; ricorda che molte regole girano solo se compare una loro `keyword` nel file |
| Regola non compilabile | `python js_analyzer.py --check-rules`, poi `pip install regex` |
| Crawl troppo lento | `--delay 0.3 --workers 5` (con parsimonia: sono richieste verso il target) |
| Crawl che si ferma troppo presto | alza `--stop-after-no-new` o metti `0` |
| Pagine bloccate | `robots.txt`: se l'ingaggio lo consente, `--no-robots` |
| Interrotto con Ctrl-C | rilancia lo stesso comando con `--resume` |
