"""Real frozen widget/core/history/export and honest failure-evidence acceptance. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: capture — line 116
# parameter: target — line 116
# parameter: window — line 116
# variable: load — line 122
# variable: gdi — line 123
# variable: user — line 123
# variable: pointer — line 124
# variable: arguments — line 125
# variable: library — line 125
# variable: name — line 125
# variable: result — line 125
# variable: function — line 151
# attribute: argtypes — line 152
# attribute: restype — line 152
# variable: handle — line 155
# variable: rectangle — line 156
# variable: height — line 159
# variable: width — line 159
# variable: source — line 162
# variable: destination — line 163
# variable: bitmap — line 164
# variable: previous — line 165
# variable: pixels — line 170
# variable: header — line 171
# variable: raw — line 189
# variable: scanlines — line 190
# variable: row — line 191
# variable: column — line 193
# variable: offset — line 194
# definition: chunk — line 197
# parameter: data — line 197
# parameter: name — line 197
# definition: oracle — line 219
# parameter: files — line 219
# parameter: index — line 219
# variable: graph — line 221
# variable: value — line 224
# variable: edge — line 227
# variable: direct — line 232
# variable: row — line 234
# variable: value — line 240
# variable: row — line 243
# variable: value — line 246
# variable: edge — line 248
# variable: value — line 254
# variable: row — line 255
# variable: row — line 257
# variable: value — line 261
# definition: exercise — line 269
# parameter: output — line 269
# parameter: reopen — line 269
# parameter: window — line 269
# variable: deadline — line 272
# variable: expected — line 273
# variable: receipt — line 274
# definition: persist — line 292
# definition: finish — line 298
# parameter: failed — line 298
# attribute: acceptance_result — line 300
# variable: name — line 305
# variable: raw — line 305
# variable: row — line 307
# definition: checked — line 312
# parameter: callback — line 312
# definition: wait — line 320
# parameter: callback — line 320
# definition: layout — line 330
# variable: original — line 332
# variable: button — line 346
# definition: rejected — line 369
# definition: export_and_reject — line 376
# variable: parent — line 380
# variable: original — line 382
# variable: exported — line 385
# variable: path — line 386
# definition: completed — line 395
# parameter: index — line 395
# variable: files — line 401
# definition: input_layout — line 427
# variable: widgets — line 432
# variable: name — line 433
# variable: widget — line 435
# definition: start — line 451
# parameter: index — line 451
# variable: field — line 458
# variable: relative — line 458
# variable: imported — line 462
# definition: begin — line 471
# variable: identity — line 475
# END CODE MAP

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import struct
import sys
import time
import zlib
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ztlab import desktop_project as project
from ztlab.desktop_io import json_value

if TYPE_CHECKING:
    from tkinter import ttk

    from ztlab.desktop import Workbench


def capture(window: Workbench, target: Path) -> None:
    """Capture only this owned synthetic Tk window via PrintWindow, never the user's whole desktop."""
    if sys.platform != "win32":
        raise OSError("native screenshot acceptance targets Windows")
    from ctypes import wintypes

    load = ctypes.WinDLL
    user, gdi = load("user32", use_last_error=True), load("gdi32", use_last_error=True)
    pointer = ctypes.c_void_p
    for library, name, arguments, result in [
        (user, "GetAncestor", [pointer, ctypes.c_uint], pointer),
        (user, "GetWindowDC", [pointer], pointer),
        (gdi, "CreateCompatibleDC", [pointer], pointer),
        (gdi, "CreateCompatibleBitmap", [pointer, ctypes.c_int, ctypes.c_int], pointer),
        (gdi, "SelectObject", [pointer, pointer], pointer),
        (gdi, "DeleteObject", [pointer], ctypes.c_int),
        (gdi, "DeleteDC", [pointer], ctypes.c_int),
        (user, "ReleaseDC", [pointer, pointer], ctypes.c_int),
        (user, "PrintWindow", [pointer, pointer, ctypes.c_uint], ctypes.c_int),
        (user, "GetWindowRect", [pointer, ctypes.POINTER(wintypes.RECT)], ctypes.c_int),
        (
            gdi,
            "GetDIBits",
            [
                pointer,
                pointer,
                ctypes.c_uint,
                ctypes.c_uint,
                pointer,
                pointer,
                ctypes.c_uint,
            ],
            ctypes.c_int,
        ),
    ]:
        function = getattr(library, name)
        function.argtypes, function.restype = arguments, result
    # Flush this owned native window's pending control messages before reading its pixels.
    window.root.update()
    handle = user.GetAncestor(window.root.winfo_id(), 2)
    rectangle = wintypes.RECT()
    if not user.GetWindowRect(handle, ctypes.byref(rectangle)):
        raise OSError("owned window bounds unavailable")
    width, height = rectangle.right - rectangle.left, rectangle.bottom - rectangle.top
    if not 1 <= width <= 4096 or not 1 <= height <= 4096:
        raise OSError("owned screenshot outside bounded dimensions")
    source = user.GetWindowDC(handle)
    destination = gdi.CreateCompatibleDC(source)
    bitmap = gdi.CreateCompatibleBitmap(source, width, height)
    previous = gdi.SelectObject(destination, bitmap)
    try:
        if not user.PrintWindow(handle, destination, 2):
            raise OSError("owned window rendering unavailable")
        gdi.SelectObject(destination, previous)
        pixels = ctypes.create_string_buffer(width * height * 4)
        header = ctypes.create_string_buffer(
            struct.pack(
                "<IiiHHIIiiII",
                40,
                width,
                -height,
                1,
                32,
                0,
                width * height * 4,
                0,
                0,
                0,
                0,
            )
        )
        if gdi.GetDIBits(source, bitmap, 0, height, pixels, header, 0) != height:
            raise OSError("owned screenshot pixels incomplete")
        raw = pixels.raw
        scanlines = bytearray()
        for row in range(height):
            scanlines.append(0)
            for column in range(width):
                offset = (row * width + column) * 4
                scanlines.extend((raw[offset + 2], raw[offset + 1], raw[offset]))

        def chunk(name: bytes, data: bytes) -> bytes:
            """Encode a bounded standard PNG chunk with its actual CRC."""
            return (
                struct.pack(">I", len(data))
                + name
                + data
                + struct.pack(">I", zlib.crc32(name + data))
            )

        target.write_bytes(
            b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(scanlines)))
            + chunk(b"IEND", b"")
        )
    finally:
        gdi.SelectObject(destination, previous)
        gdi.DeleteObject(bitmap)
        gdi.DeleteDC(destination)
        user.ReleaseDC(handle, source)


def oracle(index: int, files: dict[str, bytes]) -> None:
    """Require literal independent domain outcomes, not merely a normal process exit."""
    graph = json_value(files["graph.json"])
    assert len(graph["nodes"]) == 4
    if index == 0:
        value = json_value(files["evaluation.json"])
        assert value["case_count"] == value["oracle_matches"] == 57
        assert len(value["transport_matrix"]) == 48
        assert {tuple(edge) for edge in graph["edges"]} == {
            ("web", "api", 8080),
            ("api", "db", 8080),
        }
        assert value["possible_application_pivots"]["web"] == ["api", "db"]
        direct = next(
            row
            for row in value["transport_matrix"]
            if row["flow"]
            == {"source": "web", "target": "db", "protocol": "tcp", "port": 8080}
        )
        assert direct["decision"]["allowed"] is False
    elif index == 1:
        value = json_value(files["evaluation.json"])
        assert value["case_count"] == 57 and value["oracle_matches"] < 57
        assert graph["edges"] == [] and all(
            not row["decision"]["allowed"] for row in value["transport_matrix"]
        )
    elif index == 2:
        value = json_value(files["result.json"])
        assert value["added"] == []
        assert {tuple(edge) for edge in value["removed"]} == {
            ("web", "api", 8080),
            ("api", "db", 8080),
        }
        assert graph["edges"] == []
    elif index == 3:
        value = json_value(files["continuity.json"])
        assert [row["tick"] for row in value["timeline"]] == [1000, 1299, 1300]
        assert len(value["review_queue"]) == 2 and {
            row["tick"] for row in value["review_queue"]
        } == {1300}
        assert graph["tick"] == 1300 and graph["edges"] == []
    else:
        value = json_value(files["result.json"])
        assert (
            value["admission"]["allowed"] is False
            and value["transport"]["allowed"] is True
        )
        assert "identity" in value["admission"]["reason"]


def exercise(window: Workbench, output: Path, reopen: bool) -> None:
    """Drive the SAME real widgets/worker/core/SQLite; retain failed receipts, never retry or use a normal profile."""
    output.mkdir(mode=0o700)
    deadline = time.monotonic() + 55
    expected = len(project.SCENARIOS)
    receipt: dict[str, Any] = {
        "schema": 1,
        "product": project.PRODUCT,
        "version": project.VERSION,
        "source": window.identity.get("source"),
        "source_dirty": window.identity.get("source_dirty"),
        "python_version": sys.version.split()[0],
        "python_dll_sha256": window.identity.get("python_dll_sha256"),
        "pid": os.getpid(),
        "parent_pid": os.getppid(),
        "synthetic": True,
        "reopen": reopen,
        "passed": False,
        "steps": [],
        "tcl_version": str(window.root.tk.call("info", "patchlevel")),
        "tk_version": str(window.root.tk.call("package", "require", "Tk")),
    }

    def persist() -> None:
        """Save bounded synthetic aggregate facts without original input paths, secrets or private stores."""
        (output / "acceptance.json").write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
        )

    def finish(failed: bool = False) -> None:
        """Keep each exact retained file fingerprint and request only normal application shutdown."""
        window.acceptance_result = not failed
        receipt["passed"] = not failed
        receipt["bundles"] = {
            str(row["id"]): {
                name: hashlib.sha256(raw).hexdigest()
                for name, raw in window.state.files(row["id"]).items()
            }
            for row in window.state.history()
        }
        persist()
        window.exit()

    def checked(callback: Any) -> None:
        """An oracle failure remains a failed receipt and never silently re-runs the app or clears saved history."""
        try:
            callback()
        except Exception:
            receipt["failure_stage"] = callback.__name__
            finish(True)

    def wait(callback: Any) -> None:
        """Poll only this actual owned worker under a fixed deadline, allowing normal Tk mainloop work."""
        if time.monotonic() > deadline:
            receipt["failure_stage"] = "owned-operation-deadline"
            finish(True)
        elif window.busy:
            window.root.after(60, lambda: wait(callback))
        else:
            checked(callback)

    def layout() -> None:
        """Require all lifecycle controls and full long status at the actual supported minimum viewport."""
        original = window.status.get()
        window.root.geometry("980x700")
        window.status.set(
            original
            + " Synthetic long-message layout check: existing evidence remains available and Exit waits for the owned operation."
        )
        window.root.update()
        assert (
            int(window.status_label.cget("wraplength"))
            <= window.status_label.winfo_width()
        )
        assert (
            window.status_label.winfo_height() >= window.status_label.winfo_reqheight()
        )
        for button in window.footer_buttons.values():
            assert button.winfo_width() >= button.winfo_reqwidth()
            assert button.winfo_rootx() >= window.root.winfo_rootx()
            assert (
                button.winfo_rootx() + button.winfo_width()
                <= window.root.winfo_rootx() + window.root.winfo_width()
            )
            assert (
                button.winfo_rooty() + button.winfo_height()
                <= window.root.winfo_rooty() + window.root.winfo_height()
            )
        receipt["layout"] = {
            "root": [window.root.winfo_width(), window.root.winfo_height()],
            "allLifecycleControlsVisible": True,
            "longStatusFullyWrapped": True,
        }
        receipt["steps"].append(
            "real-minimum-width-long-status-all-lifecycle-controls-visible"
        )
        window.status.set(original)
        window.root.geometry("1260x860")
        window.root.update()

    def rejected() -> None:
        """The deliberate invalid source input cannot add or overwrite a previously retained analysis."""
        assert len(window.state.history()) == expected
        assert "rejected" in window.status.get().lower()
        receipt["steps"].append("actual-invalid-input-retains-original-history")
        finish()

    def export_and_reject() -> None:
        """Invoke the real Export handler with only a controlled OS file-picker response, then reject actual bad data."""
        from unittest.mock import patch

        parent = output / "private-export"
        parent.mkdir()
        original = window.state.files(window.selected_run)
        with patch("ztlab.desktop.filedialog.askdirectory", return_value=str(parent)):
            window.export_button.invoke()
        exported = next(parent.iterdir())
        assert {path.name: path.read_bytes() for path in exported.iterdir()} == original
        receipt["steps"].append("actual-widget-exact-export")
        window.mode.set(project.MODES[2])
        window.values["start"].set("1000")
        window.values["end"].set("4601")
        window.authorized.set(True)
        window.run_button.invoke()
        wait(rejected)

    def completed(index: int) -> None:
        """Check independent domain oracles against actual saved bytes and capture only this owned synthetic window."""
        assert (
            len(window.state.history()) == index + 1
            and window.selected_run == index + 1
        )
        files = window.state.files(index + 1)
        oracle(index, files)
        if index == 0:
            layout()
        if index == 0:
            window.tabs.tk.call(str(window.tabs), "select", str(window.graph_page))
            window.root.update()
            assert len(window.graph_canvas.find_withtag("permission")) == 2
            assert len(window.graph_canvas.find_withtag("workload")) == 4
            capture(window, output / "selected-evidence.png")
        elif index == 3:
            window.view.set("Boundary owner review queue")
            window.search.set("")
            window.render()
            assert len(window.table.get_children()) == 2
            window.table.selection_set("0")
            window.inspect()
            window.root.update()
            assert json.loads(window.details.get("1.0", "end"))["tick"] == 1300
            capture(window, output / "owner-unknown-review.png")
        receipt["steps"].append("actual-core-scenario-" + str(index + 1))
        if index + 1 == expected:
            export_and_reject()
        else:
            start(index + 1)

    def input_layout() -> None:
        """At minimum size, every active real parameter/chooser and Run control remains fully reachable."""
        window.root.geometry("980x700")
        window.tabs.tk.call(str(window.tabs), "select", str(window.inputs_page))
        window.root.update()
        widgets: list[ttk.Widget] = [window.run_button]
        for name in project.ACTIVE_FIELDS[window.mode.get()]:
            widgets.extend(window.field_widgets[name])
        for widget in widgets:
            assert widget.winfo_ismapped()
            assert widget.winfo_rootx() >= window.root.winfo_rootx()
            assert widget.winfo_rooty() >= window.root.winfo_rooty()
            assert (
                widget.winfo_rootx() + widget.winfo_width()
                <= window.root.winfo_rootx() + window.root.winfo_width()
            )
            assert (
                widget.winfo_rooty() + widget.winfo_height()
                <= window.root.winfo_rooty() + window.root.winfo_height()
            )
        receipt["steps"].append("actual-minimum-width-active-inputs-and-run-visible")
        window.root.geometry("1260x860")
        window.root.update()

    def start(index: int) -> None:
        """Prepared cases only populate ordinary controls; external source selection and explicit Run are real."""
        window.prepared.set(project.SCENARIOS[index])
        window.load_prepared()
        assert not window.authorized.get()
        input_layout()
        if index == 0:
            for field, relative in (
                ("policy", "examples/policy.json"),
                ("cases", "examples/requests.jsonl"),
            ):
                imported = output / ("selected-external-" + Path(relative).name)
                imported.write_bytes((project.ROOT / relative).read_bytes())
                window.values[field].set(str(imported))
            assert not window.authorized.get()
            receipt["steps"].append("actual-user-selected-external-input")
        window.authorized.set(True)
        window.run_button.invoke()
        wait(lambda: completed(index))

    def begin() -> None:
        """A second real process opens every prior exact bundle without recalculating it."""
        if reopen:
            assert len(window.state.history()) == expected
            for identity in range(1, expected + 1):
                window.history_table.selection_set(str(identity))
                window.open_button.invoke()
                assert window.selected_run == identity
                oracle(identity - 1, window.state.files(identity))
            receipt["steps"].append("actual-process-reopen-all-exact-bundles")
            finish()
        else:
            assert window.state.history() == []
            window.run_button.invoke()
            assert (
                window.state.history() == []
                and "permission" in window.status.get().lower()
            )
            start(0)

    checked(begin)
