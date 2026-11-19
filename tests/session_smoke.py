"""Linux CLI smoke test and synthetic short-lived-artifact probe (no malware).

Usage: python3 tests/session_smoke.py /absolute/path/to/FileGuardian
Run with DOTNET_ROOT pointing to the installed runtime if using a framework-dependent apphost.
Observed lifetime results are measurements, not capture guarantees.
"""
import collections
import hashlib
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import tempfile
import threading
import time


def main():
    executable = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix="fg-session-smoke-") as temp:
        root = Path(temp)
        monitor, evidence = root / "Monitor", root / "Evidence"
        monitor.mkdir()
        for i in range(100):
            (monitor / f"baseline-{i}.txt").write_text("not session evidence")
        home = root / "home"
        home.mkdir()
        env = dict(os.environ, HOME=str(home), XDG_DATA_HOME=str(home / "data"))
        process = subprocess.Popen(
            [executable, "cli", str(monitor), str(evidence)],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        lines = []
        messages = queue.Queue()

        def read():
            for line in process.stdout:
                lines.append(line)
                messages.put(line)

        threading.Thread(target=read, daemon=True).start()
        expected = {}
        groups = collections.defaultdict(list)
        try:
            deadline = time.monotonic() + 30
            while True:
                line = messages.get(timeout=max(0.1, deadline - time.monotonic()))
                if "Armed. Session" in line:
                    break
                if time.monotonic() > deadline:
                    raise AssertionError("engine did not arm")
            # Wait beyond one full reconciliation interval: baseline stays metadata-only.
            time.sleep(2.3)
            assert not any("[CAPTURE]" in line for line in lines), "pre-existing files were copied"
            (monitor / "baseline-0.txt").write_text("changed during analysis")
            (monitor / "payload.tmp").write_bytes(b"synthetic payload, never execute")
            (monitor / "empty-marker.lock").touch()
            for lifetime in (0, 1, 10, 50):
                for i in range(20):
                    name = f"ephemeral-{lifetime}ms-{i}.bin"
                    data = f"synthetic artifact {name}".encode()
                    prepared = root / "prepared.bin"
                    prepared.write_bytes(data)
                    prepared.rename(monitor / name)
                    if lifetime:
                        time.sleep(lifetime / 1000)
                    (monitor / name).unlink()
                    expected[name] = hashlib.sha256(data).hexdigest()
                    groups[lifetime].append(name)
            time.sleep(3)
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            process.wait(timeout=40)
        assert process.returncode == 0, "".join(lines[-20:])
        index = evidence / ".fileguardian" / "index.jsonl"
        entries = [json.loads(line) for line in index.read_text().splitlines()]
        captures = [e["Capture"] for e in entries if e["Type"] == "capture"]
        assert captures, "no session captures"
        assert all(c["SessionId"] and c["ObservedUtc"] and c["Trigger"] for c in captures)
        assert not any(c["RelativePath"].startswith("baseline-") and c["RelativePath"] != "baseline-0.txt"
                       for c in captures), "untouched baseline copied"
        assert any(c["RelativePath"] == "baseline-0.txt" and c["CapturedLength"] > 0 for c in captures)
        assert any(c["RelativePath"] == "payload.tmp" and c["CapturedLength"] > 0 for c in captures)
        assert any(c["RelativePath"] == "empty-marker.lock" and c["CapturedLength"] == 0 for c in captures)
        assert any(e["Type"] == "analysis" for e in entries), "built-in analysis did not run"
        found = set()
        for capture in captures:
            data = (evidence / capture["StoredPath"]).read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            assert digest == capture["Sha256"]
            if expected.get(capture["RelativePath"]) == digest:
                found.add(capture["RelativePath"])
        print("Untouched baseline files copied: 0 / 100")
        print("Modified baseline, .tmp payload, empty marker: preserved")
        print("Built-in plugins: analysis persisted; extension advisory did not discard evidence")
        print("All saved content SHA-256 values verified")
        for lifetime, names in groups.items():
            print(f"Synthetic lifetime {lifetime} ms: {sum(n in found for n in names)} / {len(names)} preserved")
        for line in lines:
            if "queue drops=" in line:
                print(line.strip())


if __name__ == "__main__":
    main()
