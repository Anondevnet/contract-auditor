"""Phase 28: the AI audit must not report a silent clean run when Slither analyzed nothing."""
from types import SimpleNamespace

from auditor.analysis.slither_runner import required_analysis_verdict
import auditor.ai_agent as agent


def _run(stderr, ok=True):
    return SimpleNamespace(ok=ok, stderr=stderr, status="completed", error=None)


def test_zero_contracts_is_incomplete():
    c, r = required_analysis_verdict(_run("No contract was analyzed\nx analyzed (0 contracts with 102 detectors), 0 result(s) found"))
    assert c is False and "0 contracts" in r[0]


def test_real_run_is_complete():
    assert required_analysis_verdict(_run("x analyzed (12 contracts with 102 detectors)")) == (True, [])


def test_none_is_unknown():
    assert required_analysis_verdict(None) == (None, [])


def test_analyzer_set_includes_privileged_auth_and_honeypot(monkeypatch):
    import inspect
    src = inspect.getsource(agent._run_analyzers)
    assert "privileged_auth_analyze" in src and "honeypot_analyze" in src


def test_job_inconclusive_message(monkeypatch):
    from auditor.dashboard import jobs as J
    src = open(J.__file__).read()
    assert "AI audit inconclusive" in src and 'compile_options=request.get("compile_options")' in src


def test_recorded_compile_options_unknown_returns_none(tmp_path, monkeypatch):
    import auditor.monitor as M
    from auditor.dashboard.routes import _recorded_compile_options
    monkeypatch.setattr(M, "default_monitor_db_path", lambda: tmp_path / "absent.db")
    assert _recorded_compile_options(tmp_path) is None


def test_internal_sender_revert_helper_is_a_guard():
    from pathlib import Path
    from auditor.analysis.base import AnalysisContext
    from auditor.analysis import privileged_auth as pa
    fix = Path(__file__).resolve().parent.parent / "benchmarks" / "fixtures"

    def run(name):
        c = AnalysisContext(); c.source_files = [fix / name]
        return [f for f in pa.analyze(c).findings
                if f.affected_function == "collectFees" and "unprotected" in f.title]
    assert run("PAUTH-013-locker-helper-guard-safe.sol") == []
    assert run("PAUTH-014-locker-helper-noguard.sol")
