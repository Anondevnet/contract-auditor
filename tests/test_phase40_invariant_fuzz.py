import json
import shutil
import pytest
from auditor import invariant_fuzz as I

_needs_forge = pytest.mark.skipif(not shutil.which("forge") or I._forge_std() is None,
                                reason="forge / local forge-std not available")


@_needs_forge
def test_generator_catches_leak_and_passes_safe(tmp_path):
    safe = I.generate("safe", mode="local", offset=10**6, runs=32, depth=16, budget=10**21, victim=10**21, out_root=tmp_path)
    leak = I.generate("leak", mode="local", offset=10**6, leak_bps=300, runs=32, depth=16, budget=10**21, victim=10**21, out_root=tmp_path)
    assert I.run(safe)["status"] == "pass"
    r = I.run(leak)
    assert r["violations"] == ["invariant_attackerNoProfit"] and "manual validation" in r["label"]


@_needs_forge
def test_fork_mode_requires_pinned_block_and_address(tmp_path):
    with pytest.raises(ValueError):
        I.generate("x", mode="fork", vault="not-an-address", out_root=tmp_path)
    d = I.generate("y", mode="fork", vault="0x" + "11" * 20, out_root=tmp_path)
    with pytest.raises(ValueError):
        I.run(d, fork_block=None)


def test_rate_limit_failure_is_unknown_not_violation(tmp_path, monkeypatch):
    import subprocess, json
    d = tmp_path / "p"; d.mkdir()
    (d / "GENERATED.json").write_text(json.dumps({"mode": "local"}))
    out = ("[FAIL: failed to set up invariant testing environment: Could not make raw evm call: "
           "database error: HTTP error 429] invariant_attackerNoProfit")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 1, out, ""))
    r = I.run(d)
    assert r["status"] == "unknown" and r["violations"] == [] and r["label"] is None


def test_async_fork_generate_writes_request_claim_handler(tmp_path):
    if I._forge_std() is None:
        import pytest
        pytest.skip(
            "needs a local forge-std tree under reports/research/poc/*/lib "
            "(not shipped in this repo and not downloaded)"
        )
    d = I.generate("async_x", mode="async_fork", vault="0x" + "11" * 20, out_root=tmp_path, runs=4, depth=4)
    src = (d / "test" / "AsyncVaultInvariant.t.sol").read_text()
    assert "requestDeposit" in src and "settleHonest" in src
    assert json.loads((d / "GENERATED.json").read_text())["match_contract"] == "AsyncVaultInvariant"


def test_async_fork_requires_address(tmp_path):
    with pytest.raises(ValueError):
        I.generate("bad", mode="async_fork", vault="nope", out_root=tmp_path)
