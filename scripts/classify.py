#!/usr/bin/env python3
"""
classify.py — Phase 0 Stage 4.

For each host that served a security.txt, fetch the published policy, store the raw body,
and apply fixed, auditable classification rules. No model judgement, no inference, no
guessing: if the evidence is not in the fetched text, the answer is UNKNOWN.

Usage:
    ./classify.py                       # classify everything in research/sweep/hits.tsv
    ./classify.py --limit 50            # smoke test
    ./classify.py --host example.com    # single host, verbose

Output:
    research/policies/<host>/security.txt     raw RFC 9116 body
    research/policies/<host>/policy.<ext>     raw policy page
    research/classification.tsv               one row per host
"""
import argparse
import concurrent.futures as futures
import html
import json
import os
import re
import sys
import time
from urllib.parse import urlparse

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SWEEP = os.path.join(ROOT, "research", "sweep")
POLICIES = os.path.join(ROOT, "research", "policies")
OUTTSV = os.path.join(ROOT, "research", "classification.tsv")

UA = "authorized-security-research/1.0 (+vulnerability-disclosure-policy-review)"
HEADERS = {"User-Agent": UA, "Accept": "text/plain,text/html;q=0.9,*/*;q=0.8"}
TIMEOUT = 12
MAX_POLICY_BYTES = 2_000_000

PLATFORM_HOSTS = (
    "hackerone.com", "bugcrowd.com", "intigriti.com", "bugbase.ai", "yeswehack.com",
    "openbugbounty.org", "huntr.dev", "cobalt.io", "synack.com", "zerocopter.com",
    "hackenproof.com", "immunefi.com", "safehats.com", "redstorm.io", "hacktrophy.com",
    "inspectiv.com", "cantina.xyz", "sherlock.xyz", "topcoder.com", "synacktiv.com",
    "hackerone.net", "bugbounty.jp", "issuehunt.io", "bountysource.com", "federacy.com",
)

REWARD = re.compile(
    r"(bug\s*bounty|bounty\s*(program|reward|payment|payout)|monetary\s*reward|"
    r"cash\s*reward|we\s+pay|paid\s+out|reward\s*(range|tiers?|amounts?)|payout|"
    r"(usd|eur|gbp|rub|inr|jpy|krw|cny|brl|try|pln)\s*[\d,]+|"
    r"[$€£₽¥₹₺]\s?[\d,]{3,}|up\s+to\s+[$€£₽¥₹₺]\s?[\d,]{3,}|"
    # non-English reward language — programs are not all written in English
    r"вознагражд|награда|выплат|руб\.?|"
    r"prämie|belohnung|kopfgeld|"
    r"prime\s+(de|pour)|récompense|"
    r"recompensa|prima\s+de|"
    r"recompensa\s+financeira|premiação|"
    r"premio\s+in\s+denaro|ricompensa|"
    r"赏金|奖励|悬赏|"
    r"報奨金|謝礼|"
    r"포상금|현상금|"
    r"ödül|para\s+ödülü|"
    r"hadiah|imbalan|"
    r"tiền\s+thưởng|phần\s+thưởng|"
    r"nagroda|wynagrodzenie)",
    re.I,
)
SCOPE = re.compile(
    r"(in\s*scope|out\s*of\s*scope|eligible\s*(assets?|targets?|domains?)|"
    r"scope\s*:|\bscope\b|asset\s*(list|inventory)|wildcard\s*domain|"
    r"область|в\s*рамках|исключен|"
    r"geltungsbereich|zielliste|"
    r"périmètre|hors\s*périmètre|"
    r"alcance|fuera\s*de\s*alcance|"
    r"escopo|fora\s*do\s*escopo|"
    r"范围|不在范围|"
    r"対象|対象外|"
    r"범위|대상\s*범위)", re.I)
DISCLOSE = re.compile(
    r"(vulnerability\s*disclosure|responsible\s*disclosure|coordinated\s*disclosure|"
    r"report\s*(a\s*)?(security|vulnerabilit)|security\s*research|"
    r"rules\s*of\s*engagement|safe\s*harbou?r|"
    r"уязвимост|ответственное\s*раскрытие|"
    r"schwachstelle|sicherheitslücke|"
    r"vulnérabilité|divulgation\s*responsable|"
    r"vulnerabilidad|divulgación\s*responsable|"
    r"vulnerabilidade|divulgação\s*responsável|"
    r"漏洞|安全漏洞|负责任披露|"
    r"脆弱性|責任ある開示|"
    r"취약점|책임\s*있는\s*공개|"
    r"güvenlik\s*açığı|zafiyet|"
    r"kerentanan|celah\s*keamanan|"
    r"lỗ\s*hổng|"
    r"podatność)", re.I)
NON_ASCII = re.compile(r"[^\x00-\x7f]")

# Sentence-level negation cues. A reward term only counts if the sentence carrying it is
# not negated: "we do not offer monetary rewards", "has no bug bounty", "no bounty program
# is currently offered", "no podemos establecer ningún programa de recompensas".
NEG_CUE = re.compile(
    r"\b(no|not|never|without|none|nobody|nothing|cannot|can'?t|don'?t|doesn'?t|"
    r"isn'?t|aren'?t|won'?t|neither|nor|unable|not\s+able|cannot\s+(provide|offer|pay)|"
    r"ning[uú]n|ninguna|ninguno|tampoco|"
    r"kein|keine|keinen|nicht|nie|niemals|"
    r"aucun|aucune|jamais|"
    r"não|nenhum|nenhuma|"
    r"не|нет|никогда|"
    r"没有|无|不提供|なし|ません|ありません|없|않|"
    r"tidak|bukan|không)\b", re.I)
SENT_SPLIT = re.compile(r"(?<=[.!?。！？])\s+|\n+")


STRONG_PAY = re.compile(
    r"(we\s+pay|paid\s+out|payout|pays?\s+(a\s+)?(reward|bounty|compensation)|"
    r"awards?\b|awarded|compensat|remunerat|"
    r"reward\s+(range|tier|amount|of|up\s+to)|bounty\s+(range|amount|tier|of)|"
    r"[$€£₽¥₹₺]\s?[\d,]{2,}|\d[\d,]*\s?(usd|eur|gbp|rub|inr|jpy|krw|cny|brl|try)\b|"
    r"вознагражд|выплачива|награда|"
    r"prämie|belohnung|kopfgeld|récompense|recompensa|premiação|ricompensa|"
    r"賞金|報奨金|포상금|ödül|hadiah|thưởng|nagrod)", re.I)

SEC_CONTEXT = re.compile(
    r"(bug|bounty|vulnerab|security|report|hacker|disclosure|exploit|"
    r"уязвим|ошибк|schwachstelle|sicherheit|vulnérab|sécurité|vulnerabil|seguridad|"
    r"漏洞|安全|脆弱性|취약|보안|güvenlik|zafiyet|kerentanan|keamanan|lỗ\s*hổng|"
    r"podatnoś|bezpiecze)", re.I)


MONEY = re.compile(
    r"([$\u20ac\u00a3\u20bd\u20b9\u20ba]\s?[\d,]{2,})|"
    r"(\d[\d,]*\s?(usd|eur|gbp|rub|inr|jpy|krw|cny|brl|try|aud|cad|chf)\b)", re.I)
PAYOUT_VERB = re.compile(
    r"(we\s+pay|paid\s+out|payout|pays?\s+(a\s+)?(reward|bounty|compensation)|"
    r"will\s+pay|rewards?\s+(of|range|tier|amount|up\s+to)|"
    r"bount(y|ies)\s+(of|range|amount|tier|up\s+to)|award(s|ed)?\s+(of|up\s+to)|"
    r"compensat|remunerat|"
    r"вознагражд|выплачива|награда|prämie|belohnung|kopfgeld|récompense|"
    r"recompensa|premiação|ricompensa|賞金|報奨金|포상금|ödül|hadiah|thưởng|nagrod)", re.I)


def _score(sent):
    """Specificity score for a candidate reward sentence. Higher = more likely a real payout."""
    sc = 0
    if MONEY.search(sent):
        sc += 5
    if re.search(r"up\s+to|starting\s+(at|from)|range", sent, re.I):
        sc += 2
    if PAYOUT_VERB.search(sent):
        sc += 3
    if len(sent) >= 25:
        sc += 1
    # navigation / cookie-banner / legal-boilerplate shapes
    if sent.count("|") >= 2 or sent.count("\u00b7") >= 3 or sent.count("  ") >= 4:
        sc -= 6
    words = sent.split()
    if len(words) >= 6:
        caps = sum(1 for w in words if w[:1].isupper())
        if caps / len(words) > 0.8:
            sc -= 3
    if re.search(r"(cart|checkout|subscribe|newsletter|cookie|log\s*in|sign\s*up)", sent, re.I):
        sc -= 3
    return sc


def positive_reward(text):
    """Best-scoring sentence that claims a reward, is about security, and is not negated.

    Returns (sentence, score). A bare program title ("Bug Bounty Program") scores low on
    purpose; a sentence naming an amount or a payout verb scores high.
    """
    best, best_sc = "", 0
    for sent in SENT_SPLIT.split(text or ""):
        sent = " ".join(sent.split())
        if len(sent) < 12 or len(sent) > 400:
            continue
        if not REWARD.search(sent) or not SEC_CONTEXT.search(sent):
            continue
        if not STRONG_PAY.search(sent):
            continue
        if NEG_CUE.search(sent):
            continue
        sc = _score(sent)
        if sc > best_sc:
            best, best_sc = sent, sc
    return best, best_sc


NOT_A_PROGRAM = re.compile(
    r"(antivirus|endpoint\s*protection|threat\s*intelligence|security\s*platform|"
    r"our\s+security\s+(solutions?|products?|services?))", re.I)
NEGATION = re.compile(
    r"(?:(?:does|do|did|is|are|was|were|will|would|can|may)\s+not|"
    r"don'?t|doesn'?t|isn'?t|aren'?t|won'?t|never|no\s+longer)"
    r"[^.]{0,90}?(?:offer|pay|provide|operate|run|maintain|award|compensat|reward|bounty|swag)|"
    r"(?:no|not|without)\s+(?:monetary|cash|financial|direct|paid)\s+"
    r"(?:reward|compensation|payment|bounty|incentive)|"
    r"not\s+a\s+paid|non-monetary|unpaid|"
    # non-English negation
    r"keine\s+(prämie|belohnung|kopfgeld)|kein\s+bug\s*bounty|nicht\s+vergeben|"
    r"ne\s+(verse|paie|propose|dispose)|aucune\s+récompense|pas\s+de\s+récompense|"
    r"no\s+(ofrece|paga|proporciona)|sin\s+recompensa|"
    r"não\s+(oferece|paga)|sem\s+recompensa|"
    r"не\s+(выплачива|предусматр|предоставл|является)|нет\s+(программы|вознагражд)|"
    r"不提供|没有.*(赏金|奖励)|无.*(赏金|奖励)|"
    r"提供しません|報奨金はありません|"
    r"제공하지\s*않|포상금이\s*없|"
    r"ödül\s+(vermiyor|yok)|"
    r"tidak\s+(memberikan|menyediakan)|"
    r"không\s+(có|trả|cung\s*cấp)", re.I)


def fetch(url, dest_dir, name_hint, refresh=False):
    """Fetch and store a body, with an on-disk cache so re-classification is cheap and
    evidence is written once. Returns (status, text, path, content_type) or None."""
    os.makedirs(dest_dir, exist_ok=True)
    meta_path = os.path.join(dest_dir, f"{name_hint}.meta.json")
    if not refresh and os.path.exists(meta_path):
        try:
            meta = json.load(open(meta_path, encoding="utf-8"))
            p = meta.get("path", "")
            if p and os.path.exists(p):
                raw = open(p, "rb").read()
                return (meta.get("status"), raw.decode("utf-8", errors="replace"),
                        p, meta.get("ctype", ""))
        except (json.JSONDecodeError, OSError):
            pass
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True,
                         stream=True)
        chunks, size = [], 0
        for chunk in r.iter_content(65536):
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_POLICY_BYTES:
                break
        raw = b"".join(chunks)
        enc = r.encoding or "utf-8"
        try:
            text = raw.decode(enc, errors="replace")
        except LookupError:
            text = raw.decode("utf-8", errors="replace")
        ctype = r.headers.get("Content-Type", "")
        ext = "html" if "html" in ctype else "txt"
        path = os.path.join(dest_dir, f"{name_hint}.{ext}")
        with open(path, "wb") as fh:
            fh.write(raw)
        with open(meta_path, "w", encoding="utf-8") as fh:
            json.dump({"url": url, "status": r.status_code, "ctype": ctype,
                       "path": path, "fetched_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                                  time.gmtime())}, fh)
        return r.status_code, text, path, ctype
    except requests.RequestException as exc:
        return None, f"FETCH_ERROR: {exc.__class__.__name__}: {exc}", None, ""


def parse_security_txt(text):
    """RFC 9116 field parse. Strips PGP cleartext signature blocks and comments."""
    body = text
    if "-----BEGIN PGP SIGNED MESSAGE-----" in body:
        body = body.split("-----BEGIN PGP SIGNED MESSAGE-----", 1)[1]
        if "-----BEGIN PGP SIGNATURE-----" in body:
            body = body.split("-----BEGIN PGP SIGNATURE-----", 1)[0]
        if "\n\n" in body:
            body = body.split("\n\n", 1)[1]
    fields = {}
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip().lower()
        val = val.strip()
        if key in {"contact", "policy", "expires", "encryption", "acknowledgments",
                   "preferred-languages", "canonical", "hiring", "csaf"} and val:
            fields.setdefault(key, []).append(val)
    return fields


def visible_text(text):
    """Strip markup so evidence quotes are readable prose, not HTML soup."""
    t = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", text or "")
    t = re.sub(r"(?s)<[^>]+>", " ", t)
    t = html.unescape(t)
    return re.sub(r"\s+", " ", t)


def first_sentence(text, pattern, limit=220):
    """Verbatim quote around the first match — evidence, not paraphrase."""
    vtext = visible_text(text)
    m = pattern.search(vtext)
    if not m:
        return ""
    start = max(0, m.start() - 90)
    end = min(len(vtext), m.end() + 130)
    snippet = vtext[start:end].strip()
    return snippet[:limit]


def on_platform(url):
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return None
    for p in PLATFORM_HOSTS:
        if host == p or host.endswith("." + p):
            return p
    return None


PLATFORM_NAMES = [
    ("hackerone", "hackerone.com"), ("bugcrowd", "bugcrowd.com"),
    ("intigriti", "intigriti.com"), ("bugbase", "bugbase.ai"),
    ("yeswehack", "yeswehack.com"), ("open bug bounty", "openbugbounty.org"),
    ("huntr", "huntr.dev"), ("cobalt", "cobalt.io"), ("synack", "synack.com"),
    ("immunefi", "immunefi.com"), ("hackenproof", "hackenproof.com"),
    ("zerocopter", "zerocopter.com"), ("inspectiv", "inspectiv.com"),
    ("cantina", "cantina.xyz"), ("sherlock", "sherlock.xyz"),
    ("topcoder", "topcoder.com"), ("synacktiv", "synacktiv.com"),
]


def platform_mention(text):
    """Detect 'our programme is hosted by X' style phrasing in visible text."""
    t = (text or "").lower()
    for name, host in PLATFORM_NAMES:
        pat = (rf"(hosted\s+by\s+{re.escape(name)}|"
               rf"{re.escape(name)}['’]?s?\s+(program|programme|platform|bug\s*bounty)|"
               rf"(submit|report)\w*[^.]{{0,80}}?{re.escape(name)}|"
               rf"via\s+{re.escape(name)}|"
               rf"(on|at|with|through)\s+{re.escape(name)}\b|"
               rf"partnership\s+with\s+{re.escape(name)})")
        if re.search(pat, t):
            return host
    return None


def classify_host(host, verbose=False):
    d = os.path.join(POLICIES, host)
    fields, st_body, st_path, st_status = {}, "", None, None

    for path in ("/.well-known/security.txt", "/security.txt"):
        status, text, saved, _ = fetch(f"https://{host}{path}", d, "security")
        if status == 200 and ":" in text:
            fields = parse_security_txt(text)
            if fields.get("contact") or fields.get("policy"):
                st_body, st_path, st_status = text, saved, status
                break
    if not st_body:
        # try http once, only for the canonical location
        status, text, saved, _ = fetch(f"http://{host}/.well-known/security.txt", d, "security")
        if status == 200:
            fields = parse_security_txt(text)
            if fields.get("contact") or fields.get("policy"):
                st_body, st_path, st_status = text, saved, status

    if not st_body:
        return {
            "host": host, "status": "UNKNOWN", "policy_url": "NONE",
            "evidence": "no security.txt served (or fetch blocked)",
            "evidence_path": "", "http": st_status or "ERR",
            "contact": "", "platform": "", "note": "no security.txt served",
            "confidence": "LOW",
        }

    contact = "; ".join(fields.get("contact", []))[:300]
    policy_urls = [u for u in fields.get("policy", []) if u.lower().startswith("http")]

    # a policy URL that is a platform page is decisive on its own
    for u in policy_urls:
        plat = on_platform(u)
        if plat:
            return {
                "host": host, "status": "NO - THIRD-PARTY ONLY", "policy_url": u,
                "evidence": f"security.txt Policy: {u} (platform: {plat})",
                "evidence_path": st_path, "http": st_status, "contact": contact,
                "platform": plat, "note": "policy URL is a platform page",
                "confidence": "HIGH",
            }

    policy_text, policy_path, policy_http = "", "", ""
    if policy_urls:
        policy_http, policy_text, policy_path, _ = fetch(policy_urls[0], d, "policy")

    rawblob = (policy_text or "") + "\n" + st_body
    blob = visible_text(policy_text or "") + "\n" + st_body
    plat = on_platform(policy_urls[0]) if policy_urls else None
    if not plat:
        plat = platform_mention(blob)

    sample = blob[:8000]
    non_english = bool(sample) and len(NON_ASCII.findall(sample)) > 0.05 * len(sample)
    note = "non-english policy page — read it before trusting the bucket" if non_english else ""

    has_scope = bool(SCOPE.search(blob))
    has_disclosure = bool(DISCLOSE.search(blob))
    # A reward mention only counts if the page is actually about security disclosure and
    # does not negate payment ("we do not currently offer monetary rewards" is a VDP, not a
    # bounty). Currency amounts on a marketing page are not a program.
    reward_sentence, reward_score = positive_reward(blob)
    has_reward = bool(reward_sentence) and reward_score >= 4 and (has_disclosure or has_scope)
    looks_like_vendor = bool(NOT_A_PROGRAM.search(policy_text or "")) and not has_disclosure

    if has_reward and not has_scope:
        note = (note + " | reward language found, scope not on this page — confirm scope "
                "before any testing").strip(" |")

    if plat:
        status = "NO - THIRD-PARTY ONLY"
        ev = f"program is hosted on {plat}"
        ev_path = policy_path or st_path
        if has_scope:
            note = (note + " | page also defines a scope — check for a parallel direct "
                    "channel before discarding").strip(" |")
    elif has_reward:
        status = "YES - DIRECT PAID BOUNTY"
        ev = reward_sentence[:220]
        ev_path = policy_path or st_path
    elif (policy_text or st_body) and (has_disclosure or has_scope):
        status = "YES - DIRECT VDP"
        ev = first_sentence(blob, DISCLOSE) or first_sentence(blob, SCOPE)
        ev_path = policy_path or st_path
    elif contact or fields.get("contact"):
        status = "YES - DIRECT SECURITY CONTACT"
        ev = f"security.txt Contact: {contact}"[:220]
        ev_path = st_path
    elif policy_text:
        status = "NO - NO PROGRAM FOUND"
        ev = "policy page fetched, no disclosure or reward language"
        ev_path = policy_path
    else:
        status = "UNKNOWN"
        ev = "security.txt present but no contact, no policy, or policy unreachable"
        ev_path = st_path

    if verbose:
        print(json.dumps({"host": host, "status": status, "evidence": ev}, indent=2))

    return {
        "host": host, "status": status,
        "policy_url": policy_urls[0] if policy_urls else "NONE",
        "evidence": ev, "evidence_path": ev_path or "",
        "http": policy_http or st_status, "contact": contact,
        "platform": plat or "", "note": note,
        "confidence": (
            "HIGH" if (status == "YES - DIRECT PAID BOUNTY" and has_scope
                       and not non_english and policy_path and reward_score >= 4)
            else "MEDIUM" if status.startswith("YES")
            else "LOW"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--host", default="")
    ap.add_argument("--workers", type=int, default=20)
    args = ap.parse_args()

    hosts = []
    if args.host:
        hosts = [args.host.lower()]
    else:
        path = os.path.join(SWEEP, "hits.tsv")
        if not os.path.exists(path):
            print(f"no hits file at {path} — run security_txt_sweep.sh first", file=sys.stderr)
            return 2
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.strip():
                    hosts.append(line.split("\t")[0].strip().lower())
        hosts = list(dict.fromkeys(hosts))
    if args.limit:
        hosts = hosts[: args.limit]
    if not hosts:
        print("nothing to classify", file=sys.stderr)
        return 1

    print(f"[+] classifying {len(hosts)} hosts with {args.workers} workers")
    os.makedirs(POLICIES, exist_ok=True)
    results, t0 = [], time.time()
    with futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futs = {pool.submit(classify_host, h, bool(args.host)): h for h in hosts}
        for i, fut in enumerate(futures.as_completed(futs), 1):
            try:
                results.append(fut.result())
            except Exception as exc:  # never let one host kill the run
                results.append({"host": futs[fut], "status": "UNKNOWN",
                                "policy_url": "NONE", "evidence": f"error: {exc}",
                                "evidence_path": "", "http": "ERR", "contact": "",
                                "platform": "", "note": f"error: {exc}",
                                "confidence": "LOW"})
            if i % 25 == 0:
                print(f"    {i}/{len(hosts)}  {time.time() - t0:.0f}s", flush=True)

    cols = ["host", "status", "policy_url", "evidence", "evidence_path", "http",
            "contact", "platform", "note", "confidence"]
    with open(OUTTSV, "w", encoding="utf-8") as fh:
        fh.write("\t".join(cols) + "\n")
        for r in sorted(results, key=lambda x: (x["status"], x["host"])):
            fh.write("\t".join(str(r.get(c, "")).replace("\t", " ").replace("\n", " ")
                               for c in cols) + "\n")

    tally = {}
    for r in results:
        tally[r["status"]] = tally.get(r["status"], 0) + 1
    print(f"[+] wrote {OUTTSV}")
    for k in sorted(tally):
        print(f"    {tally[k]:>6}  {k}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
