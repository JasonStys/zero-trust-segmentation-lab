"""Presentation-adapter unit tests with real core/SQLite workers; real widgets are separately frozen-tested. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: Variable — line 250
# definition: __init__ — line 253
# parameter: self — line 253
# parameter: value — line 253
# attribute: callbacks — line 255
# attribute: value — line 255
# definition: get — line 257
# parameter: self — line 257
# definition: set — line 261
# parameter: self — line 261
# parameter: value — line 261
# attribute: value — line 263
# variable: callback — line 264
# definition: trace_add — line 267
# parameter: _event — line 267
# parameter: callback — line 267
# parameter: self — line 267
# definition: Widget — line 272
# definition: __init__ — line 275
# parameter: _args — line 275
# parameter: kwargs — line 275
# parameter: self — line 275
# attribute: options — line 277
# attribute: rows — line 277
# attribute: selected — line 277
# attribute: flags — line 278
# attribute: tk — line 279
# parameter: _items — line 279
# definition: pack — line 281
# parameter: _kwargs — line 281
# parameter: self — line 281
# definition: grid — line 284
# parameter: _kwargs — line 284
# parameter: self — line 284
# definition: grid_remove — line 287
# parameter: self — line 287
# definition: columnconfigure — line 290
# parameter: _args — line 290
# parameter: _kwargs — line 290
# parameter: self — line 290
# definition: add — line 293
# parameter: _args — line 293
# parameter: _kwargs — line 293
# parameter: self — line 293
# definition: theme_use — line 296
# parameter: _args — line 296
# parameter: self — line 296
# definition: configure — line 299
# parameter: _args — line 299
# parameter: kwargs — line 299
# parameter: self — line 299
# definition: heading — line 303
# parameter: _args — line 303
# parameter: _kwargs — line 303
# parameter: self — line 303
# definition: column — line 306
# parameter: _args — line 306
# parameter: _kwargs — line 306
# parameter: self — line 306
# definition: bind — line 309
# parameter: _args — line 309
# parameter: self — line 309
# definition: yview — line 312
# parameter: _args — line 312
# parameter: self — line 312
# definition: set — line 315
# parameter: _args — line 315
# parameter: self — line 315
# definition: state — line 318
# parameter: flags — line 318
# parameter: self — line 318
# variable: flag — line 320
# definition: invoke — line 326
# parameter: self — line 326
# definition: insert — line 332
# parameter: _parent — line 332
# parameter: _position — line 332
# parameter: iid — line 332
# parameter: self — line 332
# parameter: values — line 332
# definition: delete — line 336
# parameter: items — line 336
# parameter: self — line 336
# variable: item — line 338
# attribute: selected — line 340
# variable: item — line 340
# definition: get_children — line 342
# parameter: self — line 342
# definition: selection — line 346
# parameter: self — line 346
# definition: selection_set — line 350
# parameter: identity — line 350
# parameter: self — line 350
# attribute: selected — line 353
# definition: Text — line 356
# definition: delete — line 359
# parameter: _args — line 359
# parameter: self — line 359
# attribute: text — line 361
# definition: insert — line 363
# parameter: _position — line 363
# parameter: self — line 363
# parameter: text — line 363
# attribute: text — line 365
# definition: Root — line 368
# definition: __init__ — line 371
# parameter: self — line 371
# attribute: callbacks — line 373
# attribute: destroyed — line 373
# attribute: on_loop — line 374
# definition: title — line 376
# parameter: _args — line 376
# parameter: self — line 376
# definition: geometry — line 379
# parameter: _args — line 379
# parameter: self — line 379
# definition: minsize — line 382
# parameter: _args — line 382
# parameter: self — line 382
# definition: protocol — line 385
# parameter: _event — line 385
# parameter: callback — line 385
# parameter: self — line 385
# attribute: close_callback — line 387
# definition: after — line 389
# parameter: _delay — line 389
# parameter: callback — line 389
# parameter: self — line 389
# definition: destroy — line 393
# parameter: self — line 393
# attribute: destroyed — line 395
# definition: mainloop — line 397
# parameter: self — line 397
# variable: _ — line 401
# definition: presentation — line 409
# parameter: monkeypatch — line 409
# parameter: _parent — line 414
# definition: Canvas — line 417
# definition: delete — line 420
# parameter: _args — line 420
# parameter: self — line 420
# definition: winfo_width — line 423
# parameter: self — line 423
# definition: winfo_height — line 427
# parameter: self — line 427
# definition: create_text — line 431
# parameter: _args — line 431
# parameter: _kwargs — line 431
# parameter: self — line 431
# definition: create_line — line 434
# parameter: _args — line 434
# parameter: _kwargs — line 434
# parameter: self — line 434
# definition: create_oval — line 437
# parameter: _args — line 437
# parameter: _kwargs — line 437
# parameter: self — line 437
# variable: name — line 441
# variable: messages — line 455
# parameter: _kwargs — line 457
# parameter: args — line 457
# parameter: _kwargs — line 460
# parameter: args — line 460
# definition: app — line 466
# parameter: presentation — line 466
# parameter: tmp_path — line 466
# variable: state — line 468
# variable: root — line 469
# variable: window — line 470
# definition: settle — line 480
# parameter: window — line 480
# variable: deadline — line 482
# definition: test_real_controller_run_filter_detail_history_export_and_help — line 489
# parameter: app — line 490
# parameter: monkeypatch — line 490
# parameter: presentation — line 490
# parameter: tmp_path — line 490
# parameter: _kwargs — line 516
# variable: original — line 518
# variable: exported — line 520
# variable: path — line 521
# parameter: _kwargs — line 526
# definition: test_explicit_retention_confirmation_removes_only_selected_local_copy — line 532
# parameter: app — line 533
# parameter: monkeypatch — line 533
# parameter: tmp_path — line 533
# variable: exported — line 543
# variable: original — line 544
# parameter: _args — line 545
# parameter: _kwargs — line 545
# parameter: _args — line 548
# parameter: _kwargs — line 548
# variable: path — line 551
# attribute: busy — line 552
# attribute: busy — line 555
# definition: test_input_selection_cancel_busy_failure_and_literal_row_cap — line 558
# parameter: app — line 559
# parameter: monkeypatch — line 559
# parameter: tmp_path — line 559
# variable: name — line 562
# parameter: _kwargs — line 566
# parameter: _kwargs — line 571
# parameter: _kwargs — line 574
# variable: kind — line 576
# variable: value — line 580
# parameter: _kwargs — line 581
# attribute: busy — line 584
# attribute: busy — line 590
# attribute: current — line 597
# variable: index — line 597
# definition: test_close_retains_lock_until_actual_core_transaction_finishes — line 609
# parameter: app — line 610
# parameter: monkeypatch — line 610
# parameter: tmp_path — line 610
# variable: ready — line 613
# variable: release — line 613
# variable: actual — line 614
# definition: pause — line 616
# parameter: args — line 616
# variable: reopened — line 634
# definition: test_main_native_close_and_rejected_acceptance_paths — line 641
# parameter: monkeypatch — line 642
# parameter: presentation — line 642
# parameter: tmp_path — line 642
# variable: actual — line 645
# definition: create — line 647
# parameter: root — line 647
# parameter: state — line 647
# variable: window — line 649
# attribute: on_loop — line 650
# variable: profile — line 654
# variable: reopened — line 656
# variable: unknown — line 680
# END CODE MAP

import threading
import time
from types import SimpleNamespace

import pytest

from ztlab import desktop as module
from ztlab import desktop_project as project
from ztlab.desktop_io import Rejected
from ztlab.desktop_state import Workspace


class Variable:
    """Inert presentation variable; invokes the same registered GUI trace callbacks."""

    def __init__(self, value=""):
        """Keep a scalar control value and registered change callbacks."""
        self.value, self.callbacks = value, []

    def get(self):
        """Return the current presentation control value."""
        return self.value

    def set(self, value):
        """Change a control and exercise actual application rendering callbacks."""
        self.value = value
        for callback in self.callbacks:
            callback()

    def trace_add(self, _event, callback):
        """Retain the GUI's value-change handler."""
        self.callbacks.append(callback)


class Widget:
    """Minimal inert ttk presentation adapter; no core, storage or analysis output is mocked."""

    def __init__(self, *_args, **kwargs):
        """Retain properties, rows and command closures."""
        self.options, self.rows, self.selected = kwargs, {}, ()
        self.flags = set()
        self.tk = SimpleNamespace(call=lambda *_items: None)

    def pack(self, **_kwargs):
        """Accept presentation layout."""

    def grid(self, **_kwargs):
        """Accept presentation grid coordinates."""

    def grid_remove(self):
        """Accept operation-specific hidden controls."""

    def columnconfigure(self, *_args, **_kwargs):
        """Accept resize weights."""

    def add(self, *_args, **_kwargs):
        """Accept notebook/paned-window children."""

    def theme_use(self, *_args):
        """Accept native style selection."""

    def configure(self, *_args, **kwargs):
        """Retain updated widget options."""
        self.options.update(kwargs)

    def heading(self, *_args, **_kwargs):
        """Accept a literal table heading."""

    def column(self, *_args, **_kwargs):
        """Accept table sizing."""

    def bind(self, *_args):
        """Accept event registration; tests invoke actual handlers explicitly."""

    def yview(self, *_args):
        """Accept scroll requests."""

    def set(self, *_args):
        """Accept scrollbar position updates."""

    def state(self, flags):
        """Preserve disabled controls so a simulated click cannot bypass a busy guard."""
        for flag in flags:
            if flag.startswith("!"):
                self.flags.discard(flag[1:])
            else:
                self.flags.add(flag)

    def invoke(self):
        """Invoke the actual registered command unless the control is disabled."""
        if "disabled" not in self.flags:
            return self.options["command"]()
        return None

    def insert(self, _parent, _position, *, iid, values):
        """Retain exact rows inserted by real project rendering."""
        self.rows[iid] = values

    def delete(self, *items):
        """Remove rows and their selections like a real treeview."""
        for item in items:
            self.rows.pop(item, None)
        self.selected = tuple(item for item in self.selected if item in self.rows)

    def get_children(self):
        """Return displayed row identities."""
        return tuple(self.rows)

    def selection(self):
        """Return the current selected row identity."""
        return self.selected

    def selection_set(self, identity):
        """Select one existing row like a real single-selection control."""
        assert identity in self.rows
        self.selected = (identity,)


class Text(Widget):
    """Retain literal detail output without interpreting markup or executing event fields."""

    def delete(self, *_args):
        """Clear existing literal detail text."""
        self.text = ""

    def insert(self, _position, text):
        """Retain the exact rendered detail text."""
        self.text = text


class Root:
    """Deterministic presentation event queue; actual Tk mainloops are independently exercised by frozen acceptance."""

    def __init__(self):
        """Create a fresh owned presentation root."""
        self.callbacks, self.destroyed = [], False
        self.on_loop = None

    def title(self, *_args):
        """Accept window title."""

    def geometry(self, *_args):
        """Accept initial geometry."""

    def minsize(self, *_args):
        """Accept minimum geometry."""

    def protocol(self, _event, callback):
        """Keep the application's native close callback."""
        self.close_callback = callback

    def after(self, _delay, callback):
        """Queue the actual lifecycle callback without a platform display server."""
        self.callbacks.append(callback)

    def destroy(self):
        """Mark only this owned root as closed."""
        self.destroyed = True

    def mainloop(self):
        """Run the requested test lifecycle using real application callbacks."""
        if self.on_loop:
            self.on_loop()
        for _ in range(200):
            if self.destroyed:
                return
            self.callbacks.pop(0)()
        raise AssertionError("presentation lifecycle did not close")


@pytest.fixture
def presentation(monkeypatch):
    """Replace only OS presentation surfaces; real worker, core, SQLite and export code remain active."""
    monkeypatch.setattr(module.tk, "StringVar", Variable)
    monkeypatch.setattr(module.tk, "BooleanVar", Variable)
    monkeypatch.setattr(module.tk, "Tk", Root)
    monkeypatch.setattr(module.tk, "Toplevel", lambda _parent: Root())
    monkeypatch.setattr(module.tk, "Text", Text)

    class Canvas(Widget):
        """Only the inert drawing surface is replaced; saved actual policy edges are not mocked."""

        def delete(self, *_args):
            """Clear display commands."""

        def winfo_width(self):
            """Supply a deterministic presentation width."""
            return 1000

        def winfo_height(self):
            """Supply a deterministic presentation height."""
            return 500

        def create_text(self, *_args, **_kwargs):
            """Accept an inert text command."""

        def create_line(self, *_args, **_kwargs):
            """Accept an inert edge command."""

        def create_oval(self, *_args, **_kwargs):
            """Accept an inert workload command."""

    monkeypatch.setattr(module.tk, "Canvas", Canvas)
    for name in (
        "Frame",
        "Label",
        "Notebook",
        "Combobox",
        "Entry",
        "Button",
        "Checkbutton",
        "Panedwindow",
        "Treeview",
        "Scrollbar",
        "Style",
    ):
        monkeypatch.setattr(module.ttk, name, Widget)
    messages = []
    monkeypatch.setattr(
        module.messagebox, "showinfo", lambda *args, **_kwargs: messages.append(args)
    )
    monkeypatch.setattr(
        module.messagebox, "showerror", lambda *args, **_kwargs: messages.append(args)
    )
    return messages


@pytest.fixture
def app(tmp_path, presentation):
    """Build the actual workbench controller against an isolated real durable workspace."""
    state = Workspace(tmp_path / "profile", project.PRODUCT, project.ROOT)
    root = Root()
    window = module.Workbench(root, state)
    try:
        yield window
    finally:
        if window.worker_thread:
            window.worker_thread.join(10)
            assert not window.worker_thread.is_alive()
        state.close()


def settle(window):
    """Observe completion of one actual owned analysis; no retries or invented report values."""
    deadline = time.monotonic() + 10
    while window.busy and time.monotonic() < deadline:
        window.poll()
        time.sleep(0.005)
    assert not window.busy


def test_real_controller_run_filter_detail_history_export_and_help(
    app, tmp_path, monkeypatch, presentation
):
    """Real core results drive controls, literal filters, exact private exports and history reopening."""
    app.export()
    assert "completed" in app.status.get()
    app.run_button.invoke()
    assert not app.busy and app.state.history() == []
    app.authorized.set(True)
    app.run_button.invoke()
    settle(app)
    assert app.selected_run == 1 and len(app.state.history()) == 1
    assert len(app.table.get_children()) > 0
    app.table.selection_set("0")
    app.inspect()
    assert "{" in app.details.text
    app.review_selected()
    if project.REVIEW_MODE is not None:
        assert app.mode.get() == project.REVIEW_MODE and app.authorized.get() is False
    app.search.set("not-a-supported-record-never-present")
    assert app.table.get_children() == ()
    app.inspect()
    app.search.set("")
    app.history_table.selection_set("1")
    app.open_button.invoke()
    assert "without re-running" in app.status.get()
    monkeypatch.setattr(
        module.filedialog, "askdirectory", lambda **_kwargs: str(tmp_path)
    )
    original = app.state.files(1)
    app.export_button.invoke()
    exported = next(tmp_path.glob(project.PRODUCT + "-run-*"))
    assert {path.name: path.read_bytes() for path in exported.iterdir()} == original
    app.help()
    assert "plaintext" in presentation[-1][1]
    app.licenses()
    monkeypatch.setattr(
        module.filedialog, "askdirectory", lambda **_kwargs: str(tmp_path / "missing")
    )
    app.export()
    assert "unavailable" in app.status.get()


def test_explicit_retention_confirmation_removes_only_selected_local_copy(
    app, tmp_path, monkeypatch
):
    """Cancellation preserves data; confirmation deletes one exact DB bundle without touching a prior export."""
    app.remove_history()
    assert "Select" in app.status.get()
    app.review_selected()
    app.authorized.set(True)
    app.run_button.invoke()
    settle(app)
    app.history_table.selection_set("1")
    exported = app.state.export(1, tmp_path, project.PRODUCT)
    original = app.state.files(1)
    monkeypatch.setattr(module.messagebox, "askyesno", lambda *_args, **_kwargs: False)
    app.remove_button.invoke()
    assert app.state.files(1) == original
    monkeypatch.setattr(module.messagebox, "askyesno", lambda *_args, **_kwargs: True)
    app.remove_button.invoke()
    assert app.state.history() == [] and app.selected_run == 0
    assert {path.name: path.read_bytes() for path in exported.iterdir()} == original
    app.busy = True
    app.remove_history()
    assert "Wait" in app.status.get()
    app.busy = False


def test_input_selection_cancel_busy_failure_and_literal_row_cap(
    app, tmp_path, monkeypatch
):
    """Operator mistakes do not silently run a prepared fixture, overwrite results or defeat close semantics."""
    name = project.FIELDS[0][0]
    monkeypatch.setattr(
        module.filedialog,
        "askopenfilename",
        lambda **_kwargs: str(tmp_path / "authorized.json"),
    )
    monkeypatch.setattr(
        module.filedialog,
        "askopenfilenames",
        lambda **_kwargs: ("one.json", "two.json"),
    )
    monkeypatch.setattr(
        module.filedialog, "askdirectory", lambda **_kwargs: str(tmp_path)
    )
    for kind in ("file", "files", "directory"):
        app.authorized.set(True)
        app.choose(name, kind)
        assert app.authorized.get() is False
    value = app.values[name].get()
    monkeypatch.setattr(module.filedialog, "askopenfilename", lambda **_kwargs: "")
    app.choose(name, "file")
    assert app.values[name].get() == value
    app.busy = True
    app.choose(name, "file")
    app.load_prepared()
    app.open_history()
    app.run()
    assert app.state.history() == []
    app.busy = False
    app.load_prepared()
    app.mode.set("unsupported-operation")
    app.authorized.set(True)
    app.run()
    settle(app)
    assert "rejected" in app.status.get().lower() and app.state.history() == []
    app.current = {"bounded": [{"event": str(index)} for index in range(5001)]}
    app.view.set("bounded")
    app.render()
    assert len(app.table.get_children()) == 5000
    app.search.set('"5000"')
    assert len(app.table.get_children()) == 1
    app.exit()
    app.run()
    app.poll()
    assert app.root.destroyed and app.state.lock == -1


def test_close_retains_lock_until_actual_core_transaction_finishes(
    app, tmp_path, monkeypatch
):
    """An in-flight real analysis is drained rather than abandoned, force-killed or exposed to a second owner."""
    ready, release = threading.Event(), threading.Event()
    actual = project.analyze

    def pause(*args):
        """Control only scheduling; completion still invokes the actual project core and durable output."""
        ready.set()
        assert release.wait(5)
        return actual(*args)

    monkeypatch.setattr(project, "analyze", pause)
    app.authorized.set(True)
    app.run_button.invoke()
    assert ready.wait(3)
    app.exit()
    app.poll()
    assert not app.root.destroyed and app.busy
    with pytest.raises((Rejected, OSError)):
        Workspace(app.state.path, project.PRODUCT, project.ROOT)
    release.set()
    settle(app)
    assert app.root.destroyed and app.state.lock == -1
    reopened = Workspace(app.state.path, project.PRODUCT, project.ROOT)
    try:
        assert len(reopened.history()) == 1
    finally:
        reopened.close()


def test_main_native_close_and_rejected_acceptance_paths(
    tmp_path, presentation, monkeypatch
):
    """Normal startup never auto-analyzes; test flags cannot enter existing real-profile state or claim partial success."""
    actual = module.Workbench

    def create(root, state):
        """Use actual controls/controller; request the normal close callback at the start of the event loop."""
        window = actual(root, state)
        root.on_loop = window.exit
        return window

    monkeypatch.setattr(module, "Workbench", create)
    profile = tmp_path / "normal"
    assert module.main(["--profile", str(profile)]) == 0
    reopened = Workspace(profile, project.PRODUCT, project.ROOT)
    assert reopened.history() == []
    reopened.close()
    with pytest.raises(SystemExit):
        module.main(["--acceptance-output", str(tmp_path / "output")])
    with pytest.raises(SystemExit):
        module.main(["--acceptance-reopen"])
    assert (
        module.main(
            ["--profile", str(profile), "--acceptance-output", str(tmp_path / "output")]
        )
        == 2
    )
    assert (
        module.main(
            [
                "--profile",
                str(tmp_path / "synthetic"),
                "--acceptance-output",
                str(tmp_path / "new-output"),
            ]
        )
        == 2
    )
    unknown = tmp_path / "unknown"
    unknown.mkdir()
    (unknown / "keep").write_bytes(b"unchanged")
    assert module.main(["--profile", str(unknown)]) == 2
    assert (unknown / "keep").read_bytes() == b"unchanged"
    assert presentation and "No saved evidence was reset" in presentation[-1][1]
