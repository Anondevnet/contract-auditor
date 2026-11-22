"""Multi-reviewer AI panel for findings (local/free backends only).

Three independent reviewers with distinct roles review one finding. No
reviewer sees another's answer: prompts are built from the finding and the
source only, before any vote is collected. Each vote is persisted with
model, prompt version and timestamp in an isolated, additive-only DB
(``AUDITOR_REVIEW_DB``, default ``reports/review_panel.db``) — never the
monitor or history DB.

Labels (``aggregate``):
  * ``ai_majority_suspected``        >=2 valid "yes"  -> maps to *unresolved
    suspicion* (or *statically supported* when the yes-votes cite evidence
    lines); queued for pinned-fork reproduction. It NEVER sets
    confirmed_exploitable — only a dynamically reproduced >=$1k outsider
    loss may do that, outside this module.
  * ``ai_majority_likely_fp``        >=2 valid "no" (record kept).
  * ``inconclusive``                 <3 valid votes, or no majority.
A failed reviewer (backend error / unparseable answer) is not a vote.
Backends: Ollama on loopback (``auditor.ollama``, enforced) or a stub.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

PROMPT_VERSION = "panel-v5"
VERDICTS = ("yes", "no", "inconclusive")

ROLES: Dict[str, str] = {
    "attacker": ("You are an attacker. Try to build a concrete path by which an OUTSIDER "
                 "(no privileged role) causes loss of funds, accounting manipulation, a "
                 "pool/vault drain, an exploitable mint or a permanent lock. Answer yes "
                 "only if you can state the exact call sequence and why every guard passes."),
    "defender": ("You are a defender. Look for the guards that stop this finding: access "
                 "checks, locker/callback rules, reentrancy locks, balance/debt checks, "
                 "invariants enforced at the end of a call. Answer no if a guard you can "
                 "cite by line blocks the outsider path."),
    "invariant": ("You are an accounting and invariant checker. Identify the invariants "
                  "(conservation of balances, debt settlement, share/asset ratios) this "
                  "code relies on, and decide whether the finding breaks one for an outsider."),
}

LOSS_CLASSES = [  # (priority, regex over title/detector/class/category)
    (100, r"theft|steal|drain|arbitrary.?(send|transfer)|unprotected.?(withdraw|selfdestruct)"),
    (90, r"mint|inflation|share.?price|donation"),
    (80, r"accounting|reentran|oracle|price.?manip|rounding"),
    (70, r"lock(ed)?.?(ether|fund)|permanent|stuck|frozen"),
    (60, r"access.?control|privileg|auth|initiali[sz]"),
]
SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def priority_for(f: Dict[str, Any]) -> int:
    text = " ".join(str(f.get(k) or "") for k in ("title", "detector", "vuln_class", "category"))
    base = 0
    for pr, rx in LOSS_CLASSES:
        if re.search(rx, text, re.I):
            base = pr
            break
    return base + 5 * SEV_RANK.get(str(f.get("severity") or "").upper(), 0)


@dataclass
class Vote:
    role: str
    model: str
    verdict: Optional[str]          # None => failed reviewer (not a vote)
    loss_path: str = ""
    preconditions: str = ""
    evidence_lines: List[str] = field(default_factory=list)
    confidence: Optional[float] = None
    reasoning: str = ""
    error: Optional[str] = None
    prompt_version: str = PROMPT_VERSION
    created_at: str = field(default_factory=_now)
    elapsed_s: float = 0.0

    @property
    def valid(self) -> bool:
        return self.verdict in VERDICTS and self.error is None


def aggregate(votes: Sequence[Vote]) -> Dict[str, Any]:
    valid = [v for v in votes if v.valid]
    yes = sum(v.verdict == "yes" for v in valid)
    no = sum(v.verdict == "no" for v in valid)
    out = {"valid_votes": len(valid), "yes": yes, "no": no,
           "inconclusive": len(valid) - yes - no, "failed": len(votes) - len(valid),
           "confirmed_exploitable": 0}   # never set by the panel
    ai_valid = [v for v in valid if v.model != "deterministic"]
    if len(ai_valid) < 3:
        out.update(label="inconclusive", epistemic="unresolved suspicion",
                   reason=f"only {len(ai_valid)} valid AI reviewer vote(s); need 3")
    elif yes * 2 == len(valid) or no * 2 == len(valid):
        out.update(label="inconclusive", epistemic="unresolved suspicion", reason=f"tie {yes}-{no}")
    elif yes * 2 > len(valid) and any(v.model == "deterministic" and v.verdict == "no" for v in valid):
        # Measured (panel-v3/v4 samples): the single local model voted "yes" on
        # internal onlyX functions in every role. A deterministic guard "no"
        # therefore vetoes an AI-majority yes; the finding stays unresolved.
        out.update(label="inconclusive", epistemic="unresolved suspicion",
                   reason=f"{yes} AI yes vetoed by guard_check (internal/privileged function)")
    elif yes * 2 > len(valid):
        cited = any(v.evidence_lines for v in valid if v.verdict == "yes")
        out.update(label="ai_majority_suspected",
                   epistemic="statically supported" if cited else "unresolved suspicion",
                   reason=f"{yes}-{len(valid) - yes} yes; queue pinned-fork reproduction")
    elif no * 2 > len(valid):
        out.update(label="ai_majority_likely_fp", epistemic="unresolved suspicion",
                   reason=f"{no}-{len(valid) - no} no; record kept, not deleted")
    else:
        out.update(label="inconclusive", epistemic="unresolved suspicion", reason="no majority")
    return out


_JSON_RX = re.compile(r"\{.*\}", re.S)


def parse_vote(role: str, model: str, text: Optional[str], error: Optional[str]) -> Vote:
    if error or not text:
        return Vote(role, model, None, error=error or "empty answer")
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
    m = _JSON_RX.search(text)
    try:
        d = json.loads(m.group(0)) if m else None
    except ValueError:
        d = None
    if not isinstance(d, dict):
        return Vote(role, model, None, reasoning=text[:2000], error="unparseable answer")
    verdict = str(d.get("vulnerable", "")).strip().lower()
    verdict = {"true": "yes", "false": "no"}.get(verdict, verdict)
    if verdict not in VERDICTS:
        return Vote(role, model, None, reasoning=text[:2000], error=f"bad verdict {verdict!r}")
    try:
        conf = float(d.get("confidence")) if d.get("confidence") is not None else None
        conf = None if conf is None else max(0.0, min(1.0, conf if conf <= 1 else conf / 100))
    except (TypeError, ValueError):
        conf = None
    ev = d.get("evidence_lines") or []
    return Vote(role, model, verdict, loss_path=str(d.get("loss_path") or "")[:2000],
                preconditions=str(d.get("preconditions") or "")[:2000],
                evidence_lines=[str(x)[:200] for x in (ev if isinstance(ev, list) else [ev])][:20],
                confidence=conf, reasoning=str(d.get("reasoning") or "")[:4000])


def build_prompt(role: str, finding: Dict[str, Any], source: str) -> tuple[str, str]:
    system = ROLES[role] + (" Reply with ONLY one JSON object: {\"vulnerable\": \"yes\"|\"no\"|"
                            "\"inconclusive\", \"loss_path\": str, \"preconditions\": str, "
                            "\"evidence_lines\": [\"File.sol:123\", ...], \"confidence\": 0..1, "
                            "\"reasoning\": str}. Do not invent code that is not shown. "
                            "Rules: an internal/private function is NOT callable by an outsider "
                            "unless you cite the public entry point that reaches it with "
                            "attacker-controlled arguments; a modifier such as onlyOwner/onlyRole/"
                            "only* or a msg.sender check is a guard; a detector title is a claim "
                            "to test, not evidence. If you cannot cite the outsider entry point, "
                            "answer no or inconclusive.")
    f = {k: finding.get(k) for k in ("title", "detector", "severity", "contract", "function",
                                     "file", "lines", "category")}
    # "/no_think": qwen3 soft switch — otherwise hidden reasoning can consume
    # the whole token budget and Ollama returns an empty response.
    prompt = (f"Finding:\n{json.dumps(f, default=str)}\n\nSource excerpt:\n{source[:12000]}\n\n"
              "Answer with the JSON object only. /no_think")
    return system, prompt


Backend = Callable[[str, str, str], tuple]  # (model, system, prompt) -> (text, error)


def ollama_backend(timeout: float = 300.0, max_tokens: int = 1500) -> Backend:
    from auditor.ollama import generate_completion

    def call(model: str, system: str, prompt: str):
        return generate_completion(prompt, model, timeout=timeout, max_tokens=max_tokens, system=system,
                                   think=False)
    return call


_PRIV_MOD_RE = re.compile(r"\b(only\w+|auth|requiresAuth|whenNotPaused)\b")


def deterministic_guard_vote(finding: Dict[str, Any], source: str) -> Vote:
    """Non-AI reviewer: reads the flagged function's own signature in the
    excerpt. internal/private or a privilege modifier with no shown outsider
    entry point => "no"; external/public without guard => "inconclusive"
    (it cannot prove a loss path). Never votes "yes"."""
    fn = str(finding.get("function") or "")
    m = re.search(r"function\s+" + re.escape(fn) + r"\s*\([^)]*\)([^{;]*)", source) if fn else None
    v = Vote("guard_check", "deterministic", "inconclusive")
    if not m:
        v.reasoning = "flagged function signature not in excerpt"
        return v
    sig = m.group(1)
    line = next((ln.split(":", 1)[0] for ln in source.splitlines() if m.group(0)[:40] in ln), "")
    v.evidence_lines = [f"{finding.get('file') or ''}:{line}"] if line else []
    if re.search(r"\b(internal|private)\b", sig):
        v.verdict, v.reasoning = "no", f"{fn} is {re.search(r'internal|private', sig).group(0)}: not an outsider entry point"
    elif _PRIV_MOD_RE.search(sig):
        v.verdict, v.reasoning = "no", f"{fn} guarded by modifier {_PRIV_MOD_RE.search(sig).group(0)}"
    else:
        v.reasoning = "public/external without a visible modifier guard; needs a loss path"
    v.confidence = 0.8 if v.verdict == "no" else None
    return v


def review_finding(finding: Dict[str, Any], source: str, backend: Backend,
                   models: Dict[str, str]) -> List[Vote]:
    # All prompts are built up-front from finding+source only: independence.
    prompts = {r: build_prompt(r, finding, source) for r in ROLES}
    votes = []
    for role, (system, prompt) in prompts.items():
        t0 = time.monotonic()
        try:
            text, err = backend(models[role], system, prompt)
        except Exception as exc:  # noqa: BLE001
            text, err = None, f"{type(exc).__name__}: {exc}"
        v = parse_vote(role, models[role], text, err)
        v.elapsed_s = round(time.monotonic() - t0, 2)
        votes.append(v)
    votes.append(deterministic_guard_vote(finding, source))
    return votes


# ----------------------------------------------------------------- storage
SCHEMA = """
CREATE TABLE IF NOT EXISTS review_queue(
  finding_id INTEGER PRIMARY KEY, priority INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at REAL NOT NULL DEFAULT 0,
  last_error TEXT, label TEXT, enqueued_at TEXT NOT NULL, updated_at TEXT);
CREATE TABLE IF NOT EXISTS review_votes(
  id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id INTEGER NOT NULL, round INTEGER NOT NULL,
  role TEXT NOT NULL, model TEXT NOT NULL, prompt_version TEXT NOT NULL, verdict TEXT,
  confidence REAL, loss_path TEXT, preconditions TEXT, evidence_json TEXT, reasoning TEXT,
  error TEXT, elapsed_s REAL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS review_outcomes(
  id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id INTEGER NOT NULL, round INTEGER NOT NULL,
  label TEXT NOT NULL, epistemic TEXT, summary_json TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_votes_f ON review_votes(finding_id);
"""


def default_review_db() -> Path:
    return Path(os.environ.get("AUDITOR_REVIEW_DB") or
                Path(__file__).resolve().parent.parent / "reports" / "review_panel.db")


def connect(db: Optional[Path] = None) -> sqlite3.Connection:
    p = Path(db or default_review_db())
    p.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(p), timeout=10)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    return con


def enqueue(con: sqlite3.Connection, findings: Sequence[Dict[str, Any]]) -> int:
    n = 0
    for f in findings:
        cur = con.execute("INSERT OR IGNORE INTO review_queue(finding_id,priority,enqueued_at) "
                          "VALUES(?,?,?)", (int(f["id"]), priority_for(f), _now()))
        n += cur.rowcount
    con.commit()
    return n


def save_round(con: sqlite3.Connection, finding_id: int, votes: Sequence[Vote]) -> Dict[str, Any]:
    rnd = (con.execute("SELECT COALESCE(MAX(round),0) FROM review_outcomes WHERE finding_id=?",
                       (finding_id,)).fetchone()[0]) + 1
    for v in votes:
        con.execute("INSERT INTO review_votes(finding_id,round,role,model,prompt_version,verdict,"
                    "confidence,loss_path,preconditions,evidence_json,reasoning,error,elapsed_s,"
                    "created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (finding_id, rnd, v.role, v.model, v.prompt_version, v.verdict, v.confidence,
                     v.loss_path, v.preconditions, json.dumps(v.evidence_lines), v.reasoning,
                     v.error, v.elapsed_s, v.created_at))
    agg = aggregate(votes)
    con.execute("INSERT INTO review_outcomes(finding_id,round,label,epistemic,summary_json,created_at)"
                " VALUES(?,?,?,?,?,?)", (finding_id, rnd, agg["label"], agg["epistemic"],
                                         json.dumps(agg), _now()))
    con.commit()
    return dict(agg, round=rnd)


def panel_for(con: sqlite3.Connection, finding_id: int) -> Optional[Dict[str, Any]]:
    o = con.execute("SELECT * FROM review_outcomes WHERE finding_id=? ORDER BY round DESC LIMIT 1",
                    (finding_id,)).fetchone()
    if not o:
        return None
    votes = [dict(r) for r in con.execute("SELECT role,model,prompt_version,verdict,confidence,"
             "loss_path,preconditions,evidence_json,reasoning,error,elapsed_s,created_at FROM "
             "review_votes WHERE finding_id=? AND round=? ORDER BY id", (finding_id, o["round"]))]
    return {"finding_id": finding_id, "round": o["round"], "label": o["label"],
            "epistemic": o["epistemic"], "summary": json.loads(o["summary_json"]),
            "created_at": o["created_at"], "votes": votes}


def panel_summary(con: sqlite3.Connection) -> Dict[str, Any]:
    q = {r[0]: r[1] for r in con.execute("SELECT status,COUNT(*) FROM review_queue GROUP BY 1")}
    labels = {r[0]: r[1] for r in con.execute(
        "SELECT label,COUNT(*) FROM (SELECT finding_id,label,MAX(round) FROM review_outcomes "
        "GROUP BY finding_id) GROUP BY 1")}
    rate = con.execute("SELECT AVG(elapsed_s),COUNT(*) FROM review_votes").fetchone()
    return {"queue": q, "labels": labels, "votes": rate[1],
            "avg_seconds_per_vote": None if rate[0] is None else round(rate[0], 1)}


BACKOFF_S = (60, 300, 1800)


def run_queue(con: sqlite3.Connection, load: Callable[[int], tuple], backend: Backend,
              models: Dict[str, str], limit: int = 10, min_interval_s: float = 0.0,
              now: Callable[[], float] = time.time) -> List[Dict[str, Any]]:
    """Process up to ``limit`` due items, highest priority first. ``load(fid)``
    returns ``(finding_dict, source_text)`` or raises. Inconclusive rounds with
    failed reviewers are retried with backoff (max len(BACKOFF_S) attempts)."""
    rows = con.execute("SELECT finding_id,attempts FROM review_queue WHERE status IN "
                       "('pending','retry') AND next_attempt_at<=? ORDER BY priority DESC, "
                       "finding_id LIMIT ?", (now(), limit)).fetchall()
    results = []
    for i, r in enumerate(rows):
        if i and min_interval_s:
            time.sleep(min_interval_s)
        fid, attempts = r["finding_id"], r["attempts"] + 1
        try:
            finding, source = load(fid)
            votes = review_finding(finding, source, backend, models)
            agg = save_round(con, fid, votes)
            err = None
        except Exception as exc:  # noqa: BLE001
            agg, err = {"label": "inconclusive", "failed": 3}, f"{type(exc).__name__}: {exc}"
        retry = agg.get("failed", 0) > 0 and agg["label"] == "inconclusive" and attempts < len(BACKOFF_S)
        status = "retry" if retry else "done"
        nxt = now() + BACKOFF_S[attempts - 1] if retry else 0
        con.execute("UPDATE review_queue SET status=?,attempts=?,next_attempt_at=?,last_error=?,"
                    "label=?,updated_at=? WHERE finding_id=?",
                    (status, attempts, nxt, err, agg.get("label"), _now(), fid))
        con.commit()
        results.append({"finding_id": fid, "label": agg.get("label"), "error": err, "status": status})
    return results


def asdict_vote(v: Vote) -> Dict[str, Any]:
    return asdict(v)


def monitor_loader(monitor_db: Path, context_lines: int = 60) -> Callable[[int], tuple]:
    """Read-only loader of a monitor finding and its verified-source excerpt."""
    def load(fid: int):
        con = sqlite3.connect(f"file:{monitor_db}?mode=ro", uri=True, timeout=5)
        con.row_factory = sqlite3.Row
        try:
            f = con.execute("SELECT * FROM monitor_findings WHERE id=?", (fid,)).fetchone()
            if not f:
                raise LookupError(f"finding {fid} not found")
            s = con.execute("SELECT cache_dir FROM monitor_scans WHERE id=?", (f["scan_row"],)).fetchone()
        finally:
            con.close()
        f = dict(f)
        root = Path(s[0]) if s and s[0] else None
        src = ""
        if root and f.get("file"):
            cand = [p for p in root.rglob(Path(str(f["file"])).name)][:1]
            if cand:
                lines = cand[0].read_text(errors="replace").splitlines()
                nums = [int(x) for x in re.findall(r"\d+", str(f.get("lines") or ""))] or [1]
                a, b = max(1, min(nums) - context_lines), min(len(lines), max(nums) + context_lines)
                src = "\n".join(f"{i}: {lines[i - 1]}" for i in range(a, b + 1))
        if not src:
            raise LookupError("source excerpt unavailable for finding")
        return f, src
    return load
