import json
import textwrap

from redoscope.cli import main


def write(tmp_path, name, body):
    path = tmp_path / name
    path.write_text(textwrap.dedent(body))
    return str(path)


def test_scan_exit_codes_and_json(tmp_path, capsys):
    bad = write(tmp_path, "bad.py", "import re\nX = re.compile(r'^(a+)+$')\n")
    assert main(["scan", bad, "--format", "json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["findings"][0]["status"] == "confirmed"
    assert data["findings"][0]["line"] == 2
    assert main(["scan", bad, "--fail-on", "never"]) == 0


def test_clean_scan_returns_zero(tmp_path, capsys):
    ok = write(tmp_path, "ok.py", "import re\nX = re.compile(r'^[a-z]+$')\n")
    assert main(["scan", ok]) == 0
    assert "0 confirmed, 0 suspected" in capsys.readouterr().out


def test_no_verify_marks_suspected_and_fail_on_suspected(tmp_path, capsys):
    bad = write(tmp_path, "bad.py", "import re\nX = re.compile(r'^(a+)+$')\n")
    assert main(["scan", bad, "--no-verify"]) == 0
    assert "suspected" in capsys.readouterr().out
    assert main(["scan", bad, "--no-verify", "--fail-on", "suspected"]) == 1


def test_sarif_output(tmp_path, capsys):
    bad = write(tmp_path, "bad.py", "import re\nX = re.compile(r'^(a+)+$')\n")
    main(["scan", bad, "--format", "sarif"])
    doc = json.loads(capsys.readouterr().out)
    result = doc["runs"][0]["results"][0]
    assert doc["version"] == "2.1.0"
    assert result["ruleId"] == "REDOS001" and result["level"] == "error"


def test_missing_path_is_usage_error(capsys):
    assert main(["scan", "/definitely/not/here"]) == 2
    assert "no such file" in capsys.readouterr().err


def test_check_command(capsys):
    assert main(["check", "^(a+)+$"]) == 1
    assert main(["check", "^[a-z]+$"]) == 0
    assert main(["check", "(a"]) == 2


def test_excludes_and_syntax_error_files(tmp_path, capsys):
    write(tmp_path, "broken.py", "def (:\n")
    write(tmp_path, "skip_me.py", "import re\nX = re.compile(r'^(a+)+$')\n")
    assert main(["scan", str(tmp_path), "--exclude", "skip_me.py"]) == 0
    assert "warning" in capsys.readouterr().out


def test_unmodelled_pattern_is_skipped_not_crashed(tmp_path, capsys):
    f = write(tmp_path, "c.py", "import re\nX = re.compile(r'(a)(?(1)b|c)')\n")
    assert main(["scan", f]) == 0
    assert "could not be modelled" in capsys.readouterr().out


def test_js_file_scan(tmp_path, capsys):
    f = write(tmp_path, "a.js", "const r = /^(x+)+$/;\n")
    code = main(["scan", f, "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["findings"][0]["engine"] == "v8"
    assert code in (0, 1)


def test_unconfirmed_findings_hidden_unless_requested(tmp_path, capsys):
    f = write(tmp_path, "s.py", "import re\nX = re.compile(r'(a|ab)+$')\n")
    assert main(["scan", f]) == 0
    hidden = capsys.readouterr().out
    assert "pattern:" not in hidden and "--show-suspected" in hidden
    assert main(["scan", f, "--show-suspected"]) == 0
    assert "pattern: (a|ab)+$" in capsys.readouterr().out
