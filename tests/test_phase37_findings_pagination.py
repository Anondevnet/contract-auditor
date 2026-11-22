from unittest import mock
from auditor.dashboard import routes


def _res(n, grouped=False):
    rows = [{"id": i, "source_path": "local"} for i in range(n)]
    if grouped:
        return {"total": n, "groups": {"HIGH": rows[: n // 2], "LOW": rows[n // 2:]}}
    return {"total": n, "findings": rows}


def test_flat_pages():
    with mock.patch.object(routes, "_annotate_monitor_triage"):
        p1 = routes._paginate_findings(_res(450), hide_triaged=False, limit=200, offset=0)
        p3 = routes._paginate_findings(_res(450), hide_triaged=False, limit=200, offset=400)
    assert (p1["total"], p1["returned"], p1["has_more"]) == (450, 200, True)
    assert [f["id"] for f in p3["findings"]] == list(range(400, 450)) and not p3["has_more"]


def test_limit_clamped_and_offset_nonnegative():
    with mock.patch.object(routes, "_annotate_monitor_triage"):
        p = routes._paginate_findings(_res(5), hide_triaged=False, limit=10**6, offset=-3)
    assert p["limit"] == 1000 and p["offset"] == 0 and p["returned"] == 5


def test_grouped_page_rebuilds_groups():
    with mock.patch.object(routes, "_annotate_monitor_triage"):
        p = routes._paginate_findings(_res(10, True), hide_triaged=False, limit=3, offset=4)
    assert {k: [f["id"] for f in v] for k, v in p["groups"].items()} == {"HIGH": [4], "LOW": [5, 6]}
    assert p["total"] == 10


def test_hide_triaged_counts_after_filter():
    def mark(res):
        for f in res["findings"]:
            if f["id"] % 2:
                f["monitor_triage"] = {"verdict": "False positive"}
    with mock.patch.object(routes, "_annotate_monitor_triage", side_effect=mark):
        p = routes._paginate_findings(_res(10), hide_triaged=True, limit=3, offset=0)
    assert p["total"] == 5 and [f["id"] for f in p["findings"]] == [0, 2, 4]
