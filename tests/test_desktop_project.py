"""Independent direct-versus-pivot, expiry, full16-workload export and dummy-proof GUI adapters. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: state — line 140
# parameter: tmp_path — line 140
# variable: result — line 142
# definition: run — line 149
# parameter: changes — line 149
# parameter: index — line 149
# parameter: state — line 149
# parameter: tmp_path — line 149
# variable: parameters — line 151
# variable: stage — line 152
# variable: files — line 154
# variable: kind — line 154
# variable: summary — line 154
# variable: identity — line 155
# definition: test_actual_baseline_graph_does_not_grant_transitive_connectivity — line 160
# parameter: state — line 160
# parameter: tmp_path — line 160
# variable: files — line 162
# variable: summary — line 162
# variable: report — line 163
# variable: graph — line 164
# variable: row — line 167
# variable: direct — line 172
# variable: row — line 174
# variable: name — line 183
# definition: test_quarantine_preserves_labeled_mismatches_and_exact_removed_edges — line 191
# parameter: state — line 192
# parameter: tmp_path — line 192
# variable: files — line 195
# variable: summary — line 195
# variable: report — line 196
# variable: row — line 198
# variable: _ — line 201
# variable: files — line 201
# variable: value — line 202
# variable: edge — line 204
# definition: test_expiry_reviews_only_actual_boundaries_and_graph_uses_declared_final_tick — line 212
# parameter: state — line 213
# parameter: tmp_path — line 213
# variable: files — line 216
# variable: summary — line 216
# variable: report — line 217
# variable: row — line 218
# variable: row — line 220
# variable: row — line 221
# definition: test_real_hypothetical_proof_distinguishes_transport_from_admission — line 228
# parameter: state — line 229
# parameter: tmp_path — line 229
# variable: files — line 232
# variable: summary — line 232
# variable: value — line 233
# variable: _ — line 239
# variable: files — line 239
# definition: test_all16_supported_workloads_export_every_original_file_and_one_saved_graph — line 243
# parameter: state — line 244
# parameter: tmp_path — line 244
# variable: endpoints — line 247
# variable: index — line 254
# variable: selected — line 256
# variable: cases — line 277
# variable: originals — line 294
# variable: _ — line 295
# variable: files — line 295
# variable: report — line 296
# variable: name — line 301
# definition: test_policy_changed_between_original_preview_and_graph_cannot_produce_mixed_source_evidence — line 308
# parameter: monkeypatch — line 309
# parameter: state — line 309
# parameter: tmp_path — line 309
# variable: selected — line 312
# variable: original — line 314
# definition: interleaved — line 316
# parameter: args — line 316
# definition: test_invalid_fields_never_apply_or_overwrite_accepted_evidence — line 341
# parameter: change — line 342
# parameter: state — line 342
# parameter: tmp_path — line 342
# variable: _ — line 345
# variable: files — line 345
# definition: Drawing — line 351
# definition: __init__ — line 354
# parameter: self — line 354
# attribute: commands — line 356
# definition: delete — line 358
# parameter: _args — line 358
# parameter: self — line 358
# definition: winfo_width — line 362
# parameter: self — line 362
# definition: winfo_height — line 366
# parameter: self — line 366
# definition: create_text — line 370
# parameter: args — line 370
# parameter: kwargs — line 370
# parameter: self — line 370
# definition: create_line — line 374
# parameter: args — line 374
# parameter: kwargs — line 374
# parameter: self — line 374
# definition: create_oval — line 378
# parameter: args — line 378
# parameter: kwargs — line 378
# parameter: self — line 378
# definition: test_graph_uses_exact_direct_edges_and_clear_replaces_old_markers — line 383
# parameter: state — line 383
# parameter: tmp_path — line 383
# variable: canvas — line 385
# variable: _ — line 387
# variable: kind — line 387
# variable: _ — line 388
# variable: files — line 388
# variable: row — line 390
# variable: row — line 391
# variable: row — line 392
# variable: circles — line 395
# variable: row — line 395
# variable: _ — line 396
# variable: coordinates — line 396
# variable: row — line 396
# variable: x1 — line 397
# variable: x2 — line 397
# variable: y1 — line 397
# variable: y2 — line 397
# variable: center_x — line 398
# variable: center_y — line 398
# END CODE MAP

import uuid

import pytest

from ztlab import desktop_project as project
from ztlab.contracts import canonical
from ztlab.desktop_io import Rejected, json_value
from ztlab.desktop_state import Workspace


@pytest.fixture
def state(tmp_path):
    """Use only a new synthetic owner-local profile, outside the bundled source/resources."""
    result = Workspace(
        tmp_path / "profile", project.PRODUCT, project.ROOT, synthetic=True
    )
    yield result
    result.close()


def run(state, tmp_path, index, **changes):
    """Keep real core, exact original exports and SQLite; fresh staging prevents collision errors from masking validation."""
    parameters = {**project.scenario(project.SCENARIOS[index]), **changes}
    stage = tmp_path / ("stage-" + uuid.uuid4().hex)
    stage.mkdir()
    kind, summary, files = project.analyze(state, parameters, stage)
    identity = state.save(kind, summary, parameters, files)
    assert state.files(identity) == files
    return files, summary


def test_actual_baseline_graph_does_not_grant_transitive_connectivity(state, tmp_path):
    """web→api→db is a possible pivot while direct web→db stays denied in the actual full matrix."""
    files, summary = run(state, tmp_path, 0)
    report = json_value(files["evaluation.json"])
    graph = json_value(files["graph.json"])
    assert report["oracle_matches"] == report["case_count"] == 57
    assert len(report["transport_matrix"]) == 48
    assert {tuple(row) for row in graph["edges"]} == {
        ("web", "api", 8080),
        ("api", "db", 8080),
    }
    assert report["possible_application_pivots"]["web"] == ["api", "db"]
    direct = next(
        row
        for row in report["transport_matrix"]
        if row["flow"]
        == {"source": "web", "target": "db", "protocol": "tcp", "port": 8080}
    )
    assert direct["decision"]["allowed"] is False
    assert (
        "57/57" in summary
        and len(project.views(files)["Full direct transport matrix"]) == 48
    )
    assert {name for name in files if name.endswith(".nft")} == {
        "web.nft",
        "api.nft",
        "db.nft",
        "guest.nft",
    }


def test_quarantine_preserves_labeled_mismatches_and_exact_removed_edges(
    state, tmp_path
):
    """Quarantine denies both dependencies; keeping old labels exposes drift instead of rewriting the expected outcomes."""
    files, summary = run(state, tmp_path, 1)
    report = json_value(files["evaluation.json"])
    assert report["oracle_matches"] < report["case_count"] == 57
    assert all(not row["decision"]["allowed"] for row in report["transport_matrix"])
    assert json_value(files["graph.json"])["edges"] == []
    assert "no enforcement" in summary
    files, _ = run(state, tmp_path, 2)
    value = json_value(files["result.json"])
    assert value["added"] == []
    assert {tuple(edge) for edge in value["removed"]} == {
        ("web", "api", 8080),
        ("api", "db", 8080),
    }
    assert value["before_policy_sha256"] != value["after_policy_sha256"]
    assert len(project.views(files)["Direct permission changes"]) == 2


def test_expiry_reviews_only_actual_boundaries_and_graph_uses_declared_final_tick(
    state, tmp_path
):
    """Required allow expectations do not renew expired policy; the saved end graph has no allowed direct edge."""
    files, summary = run(state, tmp_path, 3)
    report = json_value(files["continuity.json"])
    assert [row["tick"] for row in report["timeline"]] == [1000, 1299, 1300]
    assert len(report["review_queue"]) == 2
    assert {row["tick"] for row in report["review_queue"]} == {1300}
    assert all(row["decision"]["allowed"] is False for row in report["review_queue"])
    assert json_value(files["graph.json"])["tick"] == 1300
    assert json_value(files["graph.json"])["edges"] == []
    assert "final tick 1300" in summary
    assert len(project.views(files)["Boundary owner review queue"]) == 2


def test_real_hypothetical_proof_distinguishes_transport_from_admission(
    state, tmp_path
):
    """The valid direct transport rule cannot authorize an identity-mismatched dummy proof."""
    files, summary = run(state, tmp_path, 4)
    value = json_value(files["result.json"])
    assert value["transport"]["allowed"] is True
    assert value["admission"]["allowed"] is False
    assert value["admission"]["reason"] == "identity-binding"
    assert "dummy proof only" in summary
    assert len(project.views(files)["Hypothetical admission and transport"]) == 1
    files, _ = run(state, tmp_path, 4, proof="valid")
    assert json_value(files["result.json"])["admission"]["allowed"] is True


def test_all16_supported_workloads_export_every_original_file_and_one_saved_graph(
    state, tmp_path
):
    """The app's count cap admits the actual valid maximum inventory, not only its four-workload prepared example."""
    endpoints = [
        {
            "name": f"node-{index:02}",
            "tenant": "tenant-a",
            "address": f"198.18.1.{index + 1}",
            "identity": f"spiffe://lab.example/tenant-a/node-{index:02}",
        }
        for index in range(16)
    ]
    selected = tmp_path / "selected-policy.json"
    selected.write_bytes(
        canonical(
            {
                "revision": 1,
                "created_at": 1000,
                "expires_at": 1300,
                "quarantined": [],
                "endpoints": endpoints,
                "rules": [
                    {
                        "source": "node-00",
                        "target": "node-01",
                        "port": 8080,
                        "until": None,
                        "ticket": None,
                    }
                ],
            }
        )
    )
    cases = tmp_path / "selected-cases.jsonl"
    cases.write_bytes(
        canonical(
            {
                "id": "selected-direct-dependency",
                "proof_mode": "valid",
                "expected": True,
                "flow": {
                    "source": "node-00",
                    "target": "node-01",
                    "protocol": "tcp",
                    "port": 8080,
                },
            }
        )
        + b"\n"
    )
    originals = selected.read_bytes(), cases.read_bytes()
    files, _ = run(state, tmp_path, 0, policy=str(selected), cases=str(cases))
    report = json_value(files["evaluation.json"])
    assert report["oracle_matches"] == report["case_count"] == 1
    assert len(report["transport_matrix"]) == 960
    assert (
        len(files) == 19
        and len([name for name in files if name.endswith(".nft")]) == 16
    )
    assert len(json_value(files["graph.json"])["nodes"]) == 16
    assert (selected.read_bytes(), cases.read_bytes()) == originals
    assert len(state.files(1)) == 19


def test_policy_changed_between_original_preview_and_graph_cannot_produce_mixed_source_evidence(
    state, tmp_path, monkeypatch
):
    """A genuine interleaved file replacement must reject, rather than drawing one policy beside another report hash."""
    selected = tmp_path / "changing-policy.json"
    selected.write_bytes((project.ROOT / "examples/policy.json").read_bytes())
    original = project.preview

    def interleaved(*args):
        """Replace only this test-owned selected file at the actual policy read boundary."""
        selected.write_bytes(
            (project.ROOT / "examples/desktop/quarantined.json").read_bytes()
        )
        return original(*args)

    monkeypatch.setattr(project, "preview", interleaved)
    with pytest.raises(Rejected, match="changed"):
        run(state, tmp_path, 3, policy=str(selected))
    assert state.history() == []


@pytest.mark.parametrize(
    "change",
    [
        {"now": "-1"},
        {"now": "true"},
        {"port": "65536"},
        {"port": "８０８０"},
        {"proof": "load-external-plugin"},
        {"protocol": "sctp"},
        {"mode": "apply firewall"},
    ],
)
def test_invalid_fields_never_apply_or_overwrite_accepted_evidence(
    state, tmp_path, change
):
    """Closed data operations reject coercion/unsupported commands while retaining the exact previous good bundle."""
    files, _ = run(state, tmp_path, 0)
    with pytest.raises((ValueError, OSError)):
        run(state, tmp_path, 4, **change)
    assert len(state.history()) == 1 and state.files(1) == files


class Drawing:
    """Record inert canvas commands; actual Tk drawing is separately checked in the frozen app."""

    def __init__(self):
        """Retain only drawing commands for an independent edge-count oracle."""
        self.commands = []

    def delete(self, *_args):
        """Clear this display."""
        self.commands.clear()

    def winfo_width(self):
        """Use a fixed presentation width."""
        return 1000

    def winfo_height(self):
        """Use a fixed presentation height."""
        return 500

    def create_text(self, *args, **kwargs):
        """Record literal text without executing it."""
        self.commands.append(("text", args, kwargs))

    def create_line(self, *args, **kwargs):
        """Record one direct arrow."""
        self.commands.append(("line", args, kwargs))

    def create_oval(self, *args, **kwargs):
        """Record one workload marker."""
        self.commands.append(("oval", args, kwargs))


def test_graph_uses_exact_direct_edges_and_clear_replaces_old_markers(state, tmp_path):
    """Two actual direct arrows/four nodes are drawn; the extra possible pivot is never a third arrow."""
    canvas = Drawing()
    project.draw_preview(canvas, {})
    assert not any(kind == "line" for kind, _, _ in canvas.commands)
    files, _ = run(state, tmp_path, 0)
    project.draw_preview(canvas, files)
    assert len([row for row in canvas.commands if row[0] == "line"]) == 2
    assert len([row for row in canvas.commands if row[0] == "oval"]) == 4
    assert all(row[2]["arrow"] == "last" for row in canvas.commands if row[0] == "line")
    # A head at a circle's center disappears beneath later node paint and falsely
    # makes a directed permission look undirected. Inspect the actual drawing coordinates.
    circles = [row[1] for row in canvas.commands if row[0] == "oval"]
    for _, coordinates, _ in (row for row in canvas.commands if row[0] == "line"):
        for x1, y1, x2, y2 in circles:
            center_x, center_y = (x1 + x2) / 2, (y1 + y2) / 2
            assert (coordinates[2] - center_x) ** 2 + (
                coordinates[3] - center_y
            ) ** 2 > 12**2
    assert len(project.cells(next(iter(project.views(files).values()))[0])) == 4
