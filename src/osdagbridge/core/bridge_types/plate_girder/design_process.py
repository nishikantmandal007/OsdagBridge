"""
design_process.py
-----------------
Run the full analysis/design pipeline in a spawned child process so the GUI
process never inflates: the OpenSees domain, ospgrillage records and all heap
fragmentation die with the child's exit (the only guaranteed memory floor on
the Windows ucrt heap, which keeps freed pages committed).

The child streams log lines through a multiprocessing queue and ships one
DesignPayload of plain picklable data back; the parent hydrates the backend
via PlateGirderBridge.apply_design_payload(). No Qt anywhere in this module's
import graph — it must stay importable by the forkserver/spawn child.
"""
from __future__ import annotations

import dataclasses
import importlib
import multiprocessing
import os
import pickle
import queue as _queue
import sys
import time
import traceback
from dataclasses import dataclass

from osdagbridge.core.utils.logger import bridge_logger

# Hard kill delay after a cancel request goes unanswered (child stuck in a
# native solve that never reaches a check_cancel() call).
_CANCEL_KILL_GRACE_S = 20.0

# Imported by the forkserver server so children fork with the full analysis
# stack (ospgrillage / openseespy / xarray) already loaded.
_PRELOAD_MODULE = "osdagbridge.core.bridge_types.plate_girder.plategirderbridge"


@dataclass
class ResultSnapshot:
    """Picklable stand-in for the live grillage model in result handlers."""
    captured_nodes: dict    # {tag: [x, y, z]}
    captured_members: dict  # {tag: [n1, n2]}
    loads_by_case: dict     # {loadcase: [descriptor dicts]} for the 2-D scheme overlay

    # PlateGirderAnalysisResults does getattr(bridge, 'model', None).
    model = None


@dataclass
class DesignPayload:
    """Everything the GUI reads from the backend after design() completes."""
    input_dict: dict
    output_dict: dict           # plain dict — parent re-freezes to MappingProxyType
    design_results: dict
    deck_design_results: dict
    crossbracing_design_results: dict
    end_diaphragm_design_results: dict
    load_effects_cache: dict
    deflections_cache: dict
    lc_summary: dict
    reaction_summary: dict
    grillage_geometry: object
    deck_layout: object
    material_props: object
    dataset: object             # deduplicated envelope-augmented xarray Dataset
    snapshot: ResultSnapshot
    result_data: dict           # forces/displacements None — rebuilt from dataset
    design_log: list


class _ChildStdoutRedirector:
    """Line-buffer child stdout into bridge_logger stdout_print messages."""

    def __init__(self, original):
        self._original = original
        self._buffer = []

    def write(self, string):
        if self._original is not None:
            try:
                self._original.write(string)
                self._original.flush()
            except Exception:
                pass
        if not string:
            return
        self._buffer.append(string)
        if "\n" in string:
            lines = "".join(self._buffer).split("\n")
            self._buffer = [lines[-1]] if lines[-1] else []
            for line in lines[:-1]:
                if line.strip():
                    bridge_logger._emit(f"[{bridge_logger._ts()}]   {line}", "stdout_print")

    def flush(self):
        if self._original is not None:
            try:
                self._original.flush()
            except Exception:
                pass


def run_design_child(backend_path: str, input_dict: dict, msg_q, cancel_event) -> None:
    """Child-process entry point: set_input + design + ship the payload back."""
    os.environ.setdefault("MPLBACKEND", "Agg")
    parent = multiprocessing.parent_process()

    bridge_logger.add_callback(
        lambda msg, level: msg_q.put({"type": "log", "msg": msg, "level": level})
    )
    # Existing check_cancel() calls throughout the pipeline poll this; the
    # parent-alive check makes an orphaned child abort instead of running on.
    bridge_logger.add_cancel_poller(
        lambda: cancel_event.is_set() or (parent is not None and not parent.is_alive())
    )
    sys.stdout = _ChildStdoutRedirector(sys.__stdout__)

    try:
        module_name, cls_name = backend_path.rsplit(".", 1)
        backend_cls = getattr(importlib.import_module(module_name), cls_name)
        backend = backend_cls()
        backend.set_input(input_dict)
        backend.design()
        payload = backend.export_design_payload()
        try:
            blob = pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception:
            # Name the offending fields — a stray non-picklable value in the
            # payload must fail loudly, not hang the parent.
            bad = []
            for f in dataclasses.fields(payload):
                try:
                    pickle.dumps(getattr(payload, f.name))
                except Exception:
                    bad.append(f.name)
            raise TypeError(
                f"design payload is not picklable (fields: {', '.join(bad) or 'unknown'})"
            )
        msg_q.put({"type": "result", "payload_bytes": blob})
    except RuntimeError as exc:
        if "cancelled" in str(exc).lower():
            msg_q.put({"type": "cancelled"})
        else:
            msg_q.put({
                "type": "error", "exc_type": type(exc).__name__,
                "message": str(exc), "traceback": traceback.format_exc(),
            })
    except Exception as exc:
        msg_q.put({
            "type": "error", "exc_type": type(exc).__name__,
            "message": str(exc), "traceback": traceback.format_exc(),
        })


_mp_ctx = None


def _get_mp_context():
    # forkserver (preloaded) where available; spawn on Windows. fork is unsafe
    # here for the same reason as connect.design_pool: the GUI process runs Qt
    # threads whose locked mutexes a forked child would inherit.
    global _mp_ctx
    if _mp_ctx is None:
        try:
            ctx = multiprocessing.get_context("forkserver")
            ctx.set_forkserver_preload([_PRELOAD_MODULE])
            _mp_ctx = ctx
        except ValueError:
            _mp_ctx = multiprocessing.get_context("spawn")
    return _mp_ctx


def start_design_process(backend, input_dict: dict):
    """Spawn the design child. Returns (process, message_queue, cancel_event)."""
    ctx = _get_mp_context()
    msg_q = ctx.Queue()
    cancel_event = ctx.Event()
    backend_path = f"{type(backend).__module__}.{type(backend).__qualname__}"
    proc = ctx.Process(
        target=run_design_child,
        args=(backend_path, dict(input_dict), msg_q, cancel_event),
        # Not a daemon: stage 7 spawns its own design_pool children inside this
        # process, and daemonic processes may not have children. Orphan cleanup
        # is handled by the parent-alive cancel poller in run_design_child.
        daemon=False,
        name="osdagbridge-design",
    )
    proc.start()
    return proc, msg_q, cancel_event


def run_design_subprocess(backend, input_dict: dict, is_cancel_requested=None):
    """
    Blocking driver for one subprocess design run (call from a worker thread).

    Re-emits the child's log messages through the parent bridge_logger (which
    feeds the loading popup / log dock relays) and polls is_cancel_requested
    every 100 ms, setting the child's cancel event when it fires. A cancel the
    child does not honour within _CANCEL_KILL_GRACE_S gets a terminate().

    Returns (payload, error, cancelled): payload is a DesignPayload on
    success; error is {"exc_type", "message", "traceback"} on failure.
    """
    proc, msg_q, cancel_event = start_design_process(backend, input_dict)
    payload, error, cancelled = None, None, False
    cancel_time = None

    def _handle(msg):
        nonlocal payload, error, cancelled
        kind = msg.get("type")
        if kind == "log":
            bridge_logger._emit(msg["msg"], msg["level"])
        elif kind == "result":
            payload = pickle.loads(msg["payload_bytes"])
        elif kind == "cancelled":
            cancelled = True
        elif kind == "error":
            error = msg
        return kind in ("result", "cancelled", "error")

    try:
        done = False
        while not done:
            try:
                done = _handle(msg_q.get(timeout=0.1))
                continue
            except _queue.Empty:
                pass

            if not cancel_event.is_set() and is_cancel_requested is not None:
                try:
                    if is_cancel_requested():
                        cancel_event.set()
                        cancel_time = time.monotonic()
                except Exception:
                    pass

            if (cancel_time is not None and proc.is_alive()
                    and time.monotonic() - cancel_time > _CANCEL_KILL_GRACE_S):
                proc.terminate()
                cancelled = True
                break

            if not proc.is_alive():
                # Child exited: drain whatever is left, then decide.
                while True:
                    try:
                        done = _handle(msg_q.get_nowait()) or done
                    except _queue.Empty:
                        break
                if not done and not cancelled:
                    error = {
                        "exc_type": "ChildProcessError",
                        "message": f"design process exited without a result (exit code {proc.exitcode})",
                        "traceback": "",
                    }
                break
    finally:
        proc.join(10)
        if proc.is_alive():
            proc.terminate()
            proc.join(5)
        if proc.is_alive():
            proc.kill()
        msg_q.close()

    return payload, error, cancelled
