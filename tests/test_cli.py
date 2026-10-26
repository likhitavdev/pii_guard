import json
import subprocess
import sys


def run(*args, stdin=None):
    return subprocess.run(
        [sys.executable, "-m", "pii_guard", *args],
        input=stdin, capture_output=True, text=True, check=True,
    )


def test_scan_stdin_plain():
    out = run("scan", stdin="SSN 123-45-6789\n")
    assert "123-45-6789" not in out.stdout
    assert "[SSN_1_" in out.stdout
    assert "1 item(s) tokenized" in out.stderr
    assert "123-45-6789" not in out.stderr  # audit output is masked


def test_scan_file_json(tmp_path):
    f = tmp_path / "in.txt"
    f.write_text("mail jane@example.com", encoding="utf-8")
    out = run("scan", "--file", str(f), "--json")
    data = json.loads(out.stdout)
    assert data["audit"][0]["display"] == "j***@example.com"
    assert "jane@example.com" not in out.stdout
