# Windows sanity check for the cross-platform memory_guard (branch fix/windows_memory).
# Run ON THE WINDOWS BOX from the repo root of that branch:
#     python win_mem_sanity.py
# Validates, using the exact shipped code paths, that:
#   1. measurement works (real WorkingSet/Commit numbers, no "memory unavailable")
#   2. _malloc_trim() returns freed CRT heap to the OS (Commit drops)
#   3. _trim_working_set() makes the WorkingSet (Task Manager "Memory") drop
import gc
import os
import sys

os.environ["OSDAGBRIDGE_OPS_DEBUG"] = "1"
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from osdagbridge.core.utils import memory_guard as mg

assert mg._IS_WINDOWS, "run this on Windows"

ws0, commit0 = mg.log_memory("sanity: baseline")
assert ws0 is not None, "FAIL: measurement unavailable — K32GetProcessMemoryInfo broken"

# Allocate ~500 MB through the CRT heap (many mid-size blocks, like analysis data).
blocks = [bytearray(1024 * 1024) for _ in range(500)]
for b in blocks:
    b[::4096] = b"x" * len(b[::4096])  # touch pages so they land in the working set
ws1, commit1 = mg.log_memory("sanity: after 500 MB alloc")
assert commit1 - commit0 > 400, f"FAIL: alloc not visible in Commit ({commit0:.0f} -> {commit1:.0f})"

del blocks, b
gc.collect()
ws2, commit2 = mg.log_memory("sanity: after free + gc (before trim)")

mg._malloc_trim()
ws3, commit3 = mg.log_memory("sanity: after _malloc_trim")
assert commit3 - commit0 < 100, f"FAIL: Commit did not return to baseline ({commit0:.0f} -> {commit3:.0f})"

mg._trim_working_set()
ws4, commit4 = mg.log_memory("sanity: after _trim_working_set")
assert ws4 < ws1 / 2, f"FAIL: WorkingSet did not drop ({ws1:.0f} -> {ws4:.0f})"

print(f"\nPASS  WorkingSet {ws0:.0f} -> {ws1:.0f} -> {ws4:.0f} MB | "
      f"Commit {commit0:.0f} -> {commit1:.0f} -> {commit3:.0f} MB")
print("Measurement, heap trim and working-set release all work on this machine.")
