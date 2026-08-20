"""هسته‌ی مشترک CTI-Bench برای Colab.

این فایل عیناً از سامانه‌ی پژوهش برداشته شده تا اعدادِ Colab با اعدادِ قبلی
یکی باشد: همان خط‌های پایه، همان نرمال‌سازیِ تطبیق، همان امتیازدهی، همان پرامپت‌ها.
هیچ وابستگی به FastAPI یا پایگاه داده ندارد.
"""
from __future__ import annotations

import json
import math
import re

# ══════════ پرامپت‌های خلاصه‌سازی ══════════

ZEROSHOT = """You are a senior cyber threat intelligence (CTI) analyst.

Summarize the following threat intelligence report in a concise, accurate paragraph.
Focus on: the threat actor, their objectives, the attack techniques used, the targets, and the key indicators.
Do NOT invent any detail that is not present in the report. If something is unknown, omit it.

REPORT:
\"\"\"
{report}
\"\"\"

SUMMARY:"""

FEWSHOT = """You are a senior cyber threat intelligence (CTI) analyst.
Summarize threat reports concisely and accurately. Never invent details not in the report.

EXAMPLE
REPORT: A campaign by APT group "SideCopy" targeted Indian government entities using
spear-phishing emails with malicious LNK files that deployed remote access trojans such as CetaRAT.
SUMMARY: SideCopy, an APT group, targeted Indian government entities through spear-phishing emails
carrying malicious LNK files, ultimately deploying remote access trojans like CetaRAT for espionage.

Now summarize the following report in the same style.

REPORT:
\"\"\"
{report}
\"\"\"

SUMMARY:"""

TEMPLATES = {"zeroshot": ZEROSHOT, "fewshot": FEWSHOT}

def build_prompt(mode: str, report: str) -> str:
    return TEMPLATES.get(mode, ZEROSHOT).format(report=report)

# ══════════ پرامپت استخراج ساختاریافته (هدف ۱) ══════════

EXTRACT_PROMPT = """You extract structured cyber threat intelligence fields from a report.
Return STRICT JSON only (no markdown, no prose) with EXACTLY these keys, each a list of
short strings (use an empty list when nothing applies):
- "iocs": indicators of compromise — IPs, domains, URLs, file hashes, CVE IDs, emails.
  CTI reports usually write these DEFANGED so they are not clickable. Treat a defanged
  value as the indicator it stands for, and return it REFANGED (normal form):
    185[.]220[.]101[.]5   -> 185.220.101.5
    hxxp://evil[.]com/a   -> http://evil.com/a
    evil(.)com, evil{.}com, evil[dot]com -> evil.com
    user[at]evil[.]com    -> user@evil.com
  Do not skip an indicator just because it is defanged — defanged is the normal case here.
- "attack_techniques": MITRE ATT&CK technique IDs ONLY, never names. Use the base
  technique ID in the form T#### (e.g., "T1566"), not the sub-technique ("T1566.001").
  If the report names a technique without giving its ID, map it to the ID yourself.
- "threat_actor": threat actor / group names (e.g., "APT29", "Lazarus").
- "malware": malware families or tools used (e.g., "Cobalt Strike", "Emotet").
- "targeted_sectors": targeted sectors, industries, countries, or victim types.

REPORT:
{source}
"""

# ══════════ خط‌های پایه ══════════

# جمله‌های خیلی کوتاه معمولاً تیتر، شماره‌ی صفحه یا زباله‌ی استخراجِ PDF‌اند.
_MIN_SENT_WORDS = 4

# بودجه‌ی واژه — میانه‌ی طولِ خلاصه‌های مرجعِ CTISum (۱۰۹ واژه، چارکِ ۸۳–۱۳۶).
# هر دو خط پایه تا رسیدن به این بودجه جمله برمی‌دارند تا «طول» به یک متغیرِ
# مزاحم تبدیل نشود: TextRank بدون این قید ۲۷۶ واژه تولید می‌کرد (۲.۵ برابرِ
# مرجع) که ROUGE‑recall را مصنوعی بالا و precision را مصنوعی پایین می‌برد.
_WORD_BUDGET = 110
_MIN_SENTENCES = 1

_STOP = set(
    """a an the and or but if while of to in for on with by from as at is are was were be been
    being it its this that these those they them their we our you your he she his her not no
    can could may might will would should has have had do does did there here which who whom
    what when where how than then so such also into over under about after before between""".split()
)

_ABBREV = r"(?<!\b[A-Z])(?<!\bNo)(?<!\bInc)(?<!\bLtd)(?<!\bFig)(?<!\bvs)(?<!\be\.g)(?<!\bi\.e)"
# در این پیکره (استخراج‌شده از PDF) بعد از نقطه اغلب فاصله‌ای نیست
# («…the document.A few days ago…»)، پس مرزِ «نقطه + حرفِ بزرگ» هم لازم است.
_SENT_SPLIT = re.compile(
    rf"{_ABBREV}(?<=[.!?])[\"')\]]*(?:\s+|(?=[A-Z]))|\n{{2,}}"
)
_WORD = re.compile(r"[a-z0-9][a-z0-9'-]*")

def split_sentences(text: str) -> list[str]:
    """تقسیم به جمله + دور ریختنِ قطعه‌های خیلی کوتاه."""
    parts = _SENT_SPLIT.split(text or "")
    out: list[str] = []
    for p in parts:
        p = re.sub(r"\s+", " ", p).strip()
        if len(p.split()) >= _MIN_SENT_WORDS:
            out.append(p)
    return out

def _content_words(sentence: str) -> set[str]:
    return {w for w in _WORD.findall(sentence.lower()) if w not in _STOP and len(w) > 2}

def _take_within_budget(sents: list[str], order: list[int], budget: int) -> list[int]:
    """از روی `order` جمله برمی‌دارد تا بودجه‌ی واژه پر شود (دست‌کم یک جمله)."""
    picked: list[int] = []
    used = 0
    for i in order:
        n_words = len(sents[i].split())
        if picked and used + n_words > budget:
            break
        picked.append(i)
        used += n_words
        if len(picked) >= _MIN_SENTENCES and used >= budget:
            break
    return picked

def lead(text: str, budget: int = _WORD_BUDGET) -> str:
    """Lead — جمله‌های نخستِ گزارش تا سقفِ بودجه‌ی واژه."""
    sents = split_sentences(text)
    if not sents:
        return ""
    picked = _take_within_budget(sents, list(range(len(sents))), budget)
    return " ".join(sents[i] for i in picked)

def _similarity(a: set[str], b: set[str]) -> float:
    """شباهتِ متعارفِ TextRank: هم‌پوشانی نرمال‌شده با لگاریتمِ طول."""
    if not a or not b:
        return 0.0
    overlap = len(a & b)
    if overlap == 0:
        return 0.0
    denom = math.log(len(a) + 1) + math.log(len(b) + 1)
    return overlap / denom if denom else 0.0

def textrank(text: str, budget: int = _WORD_BUDGET,
             damping: float = 0.85, iterations: int = 60, tol: float = 1e-6) -> str:
    """TextRank — مرکزی‌ترین جمله‌های گراف تا سقفِ بودجه، به ترتیبِ اصلیِ متن."""
    sents = split_sentences(text)
    if not sents:
        return ""
    if len(sents) <= 2:
        return " ".join(sents)

    bags = [_content_words(s) for s in sents]
    size = len(sents)

    # ماتریس شباهت (متقارن، بدون خودحلقه)
    sim = [[0.0] * size for _ in range(size)]
    for i in range(size):
        for j in range(i + 1, size):
            w = _similarity(bags[i], bags[j])
            sim[i][j] = sim[j][i] = w

    # نرمال‌سازیِ سطری؛ سطرِ تمام‌صفر یکنواخت می‌شود تا وزن گم نشود
    for i in range(size):
        total = sum(sim[i])
        if total > 0:
            sim[i] = [v / total for v in sim[i]]
        else:
            sim[i] = [1.0 / size] * size

    # PageRank با تکرارِ توانی
    score = [1.0 / size] * size
    for _ in range(iterations):
        nxt = [(1.0 - damping) / size] * size
        for i in range(size):
            si = score[i]
            if si:
                row = sim[i]
                for j in range(size):
                    if row[j]:
                        nxt[j] += damping * si * row[j]
        if sum(abs(nxt[k] - score[k]) for k in range(size)) < tol:
            score = nxt
            break
        score = nxt

    ranked = sorted(range(size), key=lambda i: score[i], reverse=True)
    picked = _take_within_budget(sents, ranked, budget)
    return " ".join(sents[i] for i in sorted(picked))  # ترتیبِ اصلی، نه ترتیبِ امتیاز

BASELINES = {"lead3": lead, "textrank": textrank}

# ══════════ استخراج و امتیازدهی ══════════

FIELDS = ["iocs", "attack_techniques", "threat_actor", "malware", "targeted_sectors"]

def _extract_json(raw: str) -> dict:
    raw = raw.strip()
    raw = re.sub(r"^```(?:json)?|```$", "", raw, flags=re.MULTILINE).strip()
    m = re.search(r"\{.*\}", raw, flags=re.DOTALL)
    if not m:
        raise ValueError("خروجی مدل JSON معتبر نبود.")
    return json.loads(m.group(0))

def _as_list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        v = [v]
    return [str(x).strip() for x in v if str(x).strip()]

def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", str(s).strip().lower())

# --- لایه‌ی نرمال‌سازیِ تطبیق ---------------------------------------------------
# فلسفه: فقط «شکلِ نگارشی» یکسان‌سازی می‌شود، نه «هویتِ معنایی». یعنی hxxp://evil[.]com
# و http://evil.com یک چیزند و باید تطبیق بخورند؛ اما evil.com (دامنه) و
# http://evil.com (نشانی) دو شاخصِ متفاوت‌اند و عمداً یکی نمی‌شوند. همچنین نام‌های
# مستعارِ گروه‌ها (APT29 / Cozy Bear) ادغام نمی‌شوند — آن کار نیازمند دانش‌نامه است
# و ادعای سنجش را بیش از آنچه هست بزرگ می‌کند.
# این تابع عیناً روی هر دو سمتِ طلایی و پیش‌بینی اعمال می‌شود.

_DEFANG = [
    (re.compile(r"^h(?:xx|\[?x{1,2}\]?)p(s?)://", re.I), r"http\1://"),
    (re.compile(r"[\[\(\{]\s*\.\s*[\]\)\}]"), "."),
    (re.compile(r"[\[\(\{]\s*:\s*[\]\)\}]"), ":"),
    (re.compile(r"[\[\(\{]\s*(?:at|@)\s*[\]\)\}]", re.I), "@"),
    (re.compile(r"[\[\(\{]\s*dot\s*[\]\)\}]", re.I), "."),
]

_WRAP = '"\'`<>«»,;'

_RE_SUBTECH = re.compile(r"^(t\d{4})\.\d{3}$", re.I)

def _norm_match(field: str, s: str) -> str:
    """نرمال‌سازیِ مخصوصِ تطبیق — روی طلایی و پیش‌بینی یکسان اعمال می‌شود."""
    v = _norm(s).strip(_WRAP).strip()

    if field == "attack_techniques":
        # قرارداد پروژه: تکنیکِ پایه. زیرتکنیک به پایه فروکاسته می‌شود.
        m = _RE_SUBTECH.match(v)
        return m.group(1) if m else v

    if field == "iocs":
        for rx, rep in _DEFANG:
            v = rx.sub(rep, v)
        v = v.rstrip("/.")           # اسلشِ انتهاییِ نشانی و نقطه‌ی پایانِ جمله
        v = re.sub(r"^www\.", "", v)  # www. تفاوتِ معنادار نیست
        return v.strip(_WRAP).strip()

    return v

def score_extraction(pred: dict, gold: dict) -> dict:
    """Precision/Recall/F1 مبتنی بر مجموعه، میکرو-میانگین روی همه‌ی فیلدها (+ به‌تفکیک فیلد)."""
    tp = fp = fn = 0
    per_field = {}
    for f in FIELDS:
        p = {v for v in (_norm_match(f, x) for x in (pred.get(f) or [])) if v}
        g = {v for v in (_norm_match(f, x) for x in (gold.get(f) or [])) if v}
        ftp, ffp, ffn = len(p & g), len(p - g), len(g - p)
        tp += ftp; fp += ffp; fn += ffn
        per_field[f] = {"tp": ftp, "fp": ffp, "fn": ffn}

    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    if precision is not None and recall is not None and (precision + recall) > 0:
        f1 = 2 * precision * recall / (precision + recall)
    elif (tp + fp) or (tp + fn):
        f1 = 0.0
    else:
        f1 = None

    r4 = lambda v: round(v, 4) if v is not None else None
    return {"precision": r4(precision), "recall": r4(recall), "f1": r4(f1), "per_field": per_field}

def has_gold(gold: dict | None) -> bool:
    return bool(gold) and any((gold.get(f) or []) for f in FIELDS)
