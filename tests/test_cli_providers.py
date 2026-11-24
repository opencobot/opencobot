"""Tests for core/cli_providers.py. No real CLIs: fake executable
scripts on a monkeypatched PATH stand in for opencode / q / gpt."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from core.cli_providers import (  # noqa: E402
    ALLOWED_BINARIES,
    BUILTIN_CLI_PROVIDERS,
    CliProviderError,
    _batch_command_line,
    _build_argv,
    _comspec,
    _resolve_binary,
    _windows_batch_command,
    builtin_cli_config,
    run_cli_provider,
)
from core.model_gateway import ProviderConfig  # noqa: E402
from tests._cli_fakes import write_cli_fake  # noqa: E402




@pytest.fixture
def bin_dir(tmp_path, monkeypatch):
    d = tmp_path / "bin"
    d.mkdir()
    # R-012: bare CLI names resolve only against pinned dirs, never the
    # ambient PATH -- tests point the pinned dirs at the fake scripts
    # via OPENCOBOT_CLI_BIN_DIRS (operator override, same as production).
    monkeypatch.setenv("OPENCOBOT_CLI_BIN_DIRS", str(d))
    return d


def cli_config(name="opencode", **overrides):
    fields = {
        "name": name,
        "kind": "cli",
        "base_url": "",
        "model": name,
        "cli_binary": name,
        "cli_argv_template": ["{prompt}"],
        "cli_prompt_via": "arg",
        "cli_output": "stdout",
    }
    fields.update(overrides)
    return ProviderConfig(**fields)


# ---------------------------------------------------------------- happy paths

def test_opencode_fake_script_arg_mode(bin_dir):
    write_cli_fake(bin_dir, "opencode", 'printf "opencode-reply: %s\\n" "$*"\n', "@echo opencode-reply: !ARGS!\n")
    out = run_cli_provider(cli_config(), "hello world")
    assert out == "opencode-reply: hello world"


def test_gpt_fake_script_stdin_mode(bin_dir):
    write_cli_fake(bin_dir, "gpt", 'printf "stdin:"; cat; printf "\\n"\n', '<nul set /p="stdin:"\nset /p _in=\necho(%_in%\n')
    cfg = cli_config("gpt", cli_prompt_via="stdin")
    out = run_cli_provider(cfg, "read me from stdin")
    assert out == "stdin:read me from stdin"


def test_q_fake_script_json_field_output(bin_dir):
    write_cli_fake(bin_dir, "q", 'printf "{\\"text\\": \\"q-json-reply\\"}\\n"\n', '@echo {"text": "q-json-reply"}\n')
    cfg = cli_config("q", cli_output="json-field", cli_output_field="text")
    assert run_cli_provider(cfg, "anything") == "q-json-reply"


def test_prompt_via_file(bin_dir):
    write_cli_fake(bin_dir, "opencode", 'cat "$@"\n', '@type "%1"\n')
    cfg = cli_config(cli_prompt_via="file")
    assert run_cli_provider(cfg, "prompt from file") == "prompt from file"


def test_custom_cli_template(bin_dir):
    write_cli_fake(bin_dir, "custom-cli", 'printf "custom:%s\\n" "$*"\n', "@echo custom:!ARGS!\n")
    cfg = cli_config(
        "custom-cli",
        cli_argv_template=["answer", "--mode", "fast", "{prompt}"],
    )
    assert run_cli_provider(cfg, "hi") == "custom:answer --mode fast hi"


def test_stdin_prompt_never_appears_in_argv(bin_dir):
    # The script echoes its argv; the prompt must not be among them.
    write_cli_fake(bin_dir, "gpt", 'printf "argv:%s\\n" "$*"\n', "@echo argv:!ARGS!\n")
    cfg = cli_config("gpt", cli_prompt_via="stdin",
                     cli_argv_template=["run"])
    out = run_cli_provider(cfg, "top-secret-prompt")
    assert out == "argv:run"
    assert "top-secret-prompt" not in out


# ---------------------------------------------------------------- failures

def test_timeout_raises(bin_dir):
    write_cli_fake(bin_dir, "opencode", "sleep 10\n", "for /l %%i in (1,1,20000000) do rem\n")
    with pytest.raises(CliProviderError, match="timed out"):
        run_cli_provider(cli_config(), "hi", timeout=1)


def test_nonzero_exit_raises_with_stderr(bin_dir):
    write_cli_fake(bin_dir, "opencode", 'echo "boom stderr" >&2\nexit 3\n', "@echo boom stderr 1>&2\n@exit /b 3\n")
    with pytest.raises(CliProviderError, match="exited with code 3"):
        run_cli_provider(cli_config(), "hi")


def test_bad_json_raises(bin_dir):
    write_cli_fake(bin_dir, "q", 'echo "not json{"\n', "@echo not json{\n")
    cfg = cli_config("q", cli_output="json-field")
    with pytest.raises(CliProviderError, match="invalid JSON"):
        run_cli_provider(cfg, "hi")


def test_json_missing_text_field_raises(bin_dir):
    write_cli_fake(bin_dir, "q", 'printf "{\\"other\\": 1}\\n"\n', '@echo {"other": 1}\n')
    cfg = cli_config("q", cli_output="json-field")
    with pytest.raises(CliProviderError, match="no text field"):
        run_cli_provider(cfg, "hi")


def test_empty_output_raises(bin_dir):
    write_cli_fake(bin_dir, "opencode", "true\n", "@rem\n")
    with pytest.raises(CliProviderError, match="empty output"):
        run_cli_provider(cli_config(), "hi")


def test_non_cli_kind_rejected(bin_dir):
    cfg = ProviderConfig("ollama-local", "ollama", "http://localhost:11434", "llama3.1")
    with pytest.raises(CliProviderError, match="not a CLI provider"):
        run_cli_provider(cfg, "hi")


# ---------------------------------------------------------------- safety

def test_shell_metacharacters_treated_as_data(bin_dir, tmp_path):
    write_cli_fake(bin_dir, "opencode", 'printf "got:%s\\n" "$*"\n', "@echo got:!ARGS!\n")
    marker = tmp_path / "pwned"
    prompt = f"$(touch {marker}); `touch {marker}.2`; hello"
    out = run_cli_provider(cli_config(), prompt)
    assert "$(touch" in out
    assert not marker.exists()
    assert not Path(str(marker) + ".2").exists()


def test_binary_not_in_allowlist_rejected(bin_dir):
    write_cli_fake(bin_dir, "evil-bin", 'echo hi\n', "@echo hi\n")
    cfg = cli_config("evil-bin", cli_binary="evil-bin")
    with pytest.raises(CliProviderError, match="not in the allowlist"):
        run_cli_provider(cfg, "hi")


def test_binary_not_in_pinned_dirs_raises(monkeypatch):
    # R-012: the ambient PATH is never consulted -- even a fake binary
    # sitting on PATH is ignored when it is not in the pinned dirs.
    monkeypatch.delenv("OPENCOBOT_CLI_BIN_DIRS", raising=False)
    monkeypatch.setenv("PATH", "/nonexistent-dir")
    with pytest.raises(CliProviderError, match="not found in pinned binary dirs"):
        run_cli_provider(cli_config(), "hi")


def test_absolute_path_binary_with_allowlisted_basename(bin_dir, tmp_path):
    script = write_cli_fake(bin_dir, "opencode", 'printf "abs:%s\\n" "$*"\n', "@echo abs:!ARGS!\n")
    cfg = cli_config(cli_binary=str(script))
    assert run_cli_provider(cfg, "hi") == "abs:hi"


def test_absolute_path_binary_with_other_basename_rejected(bin_dir):
    script = write_cli_fake(bin_dir, "not-allowed", 'echo hi\n', "@echo hi\n")
    cfg = cli_config(cli_binary=str(script))
    with pytest.raises(CliProviderError, match="not in the allowlist"):
        run_cli_provider(cfg, "hi")


# ---------------------------------------------------------------- built-ins

def test_builtin_definitions():
    assert set(BUILTIN_CLI_PROVIDERS) == {"opencode", "kiro", "gpt", "q", "custom-cli"}
    for name in BUILTIN_CLI_PROVIDERS:
        assert BUILTIN_CLI_PROVIDERS[name]["cli_binary"] in ALLOWED_BINARIES
    # q (Amazon Q CLI) is cloud-backed; the rest are local-only.
    assert BUILTIN_CLI_PROVIDERS["q"]["egress"] == "cloud-backed"
    for name in ("opencode", "kiro", "gpt", "custom-cli"):
        assert BUILTIN_CLI_PROVIDERS[name]["egress"] == "local-only"


def test_builtin_cli_config():
    cfg = builtin_cli_config("opencode")
    assert cfg.kind == "cli"
    assert cfg.cli_binary == "opencode"
    assert cfg.is_local_only
    q_cfg = builtin_cli_config("q")
    assert q_cfg.is_cloud_backed
    with pytest.raises(ValueError, match="unknown built-in"):
        builtin_cli_config("nope")


def test_builtin_cli_config_overrides():
    cfg = builtin_cli_config("opencode", cost_per_call=0.01,
                             cli_argv_template=["run", "--model", "x", "{prompt}"])
    assert cfg.cost_per_call == 0.01
    assert cfg.cli_argv_template == ["run", "--model", "x", "{prompt}"]


# ---------------------------------------------------------------- Windows .bat/.cmd
# These tests run on Linux too: sys.platform is patched to "win32" so
# the Windows branches of _resolve_binary / _build_argv execute, and
# shutil.which honours PATHEXT (its separator is os.pathsep, so the
# test builds PATHEXT with os.pathsep.join -- ":" here, ";" on real
# Windows). Nothing here executes a .bat file or cmd.exe, so nothing
# can hang on a platform without them.

def test_windows_batch_command_line_quotes_every_element():
    # Every element double-quoted, whole command wrapped in an extra
    # pair of quotes -- the documented cmd.exe /c form (cmd strips
    # the first and last quote).
    script = "/tmp/fake-bin/opencode.bat"
    line = _batch_command_line([script, "hello world", "--flag"])
    assert line == '"' + f'"{script}" "hello world" "--flag"' + '"'


def test_windows_batch_command_line_single_element():
    assert _batch_command_line(["opencode.bat"]) == '""opencode.bat""'


def test_windows_batch_command_line_refuses_double_quote():
    # There is no escape for " inside a quoted cmd string: refuse
    # loudly instead of building a breakable command line.
    with pytest.raises(CliProviderError, match="double quote or line"):
        _batch_command_line(["opencode.bat", 'say "hi"'])


@pytest.mark.parametrize("bad", ["a" + chr(10) + "b", "a" + chr(13) + "b"])
def test_windows_batch_command_line_refuses_line_breaks(bad):
    with pytest.raises(CliProviderError, match="double quote or line"):
        _batch_command_line(["opencode.bat", bad])


def test_windows_batch_command_line_metacharacters_are_literal():
    # Inside double quotes, cmd metacharacters are literal data, so a
    # model-influenced prompt cannot inject a second command.
    line = _batch_command_line(["opencode.bat", "a & b | c > d"])
    assert line == '""opencode.bat" "a & b | c > d""'


def test_windows_comspec_env_and_fallback(monkeypatch):
    monkeypatch.setenv("COMSPEC", "/fake/cmd.exe")
    assert _comspec() == "/fake/cmd.exe"
    monkeypatch.delenv("COMSPEC")
    monkeypatch.setenv("SystemRoot", "/fake-root")
    result = _comspec()
    assert result.endswith("cmd.exe")
    assert "System32" in result


def test_windows_batch_command_returns_verbatim_string(monkeypatch):
    # The win32 batch invocation is ONE verbatim string, not a list:
    # a list element carrying the pre-quoted /c string is mangled by
    # list2cmdline (see test_windows_batch_list_form_is_broken_by_list2cmdline).
    monkeypatch.setenv("COMSPEC", "/fake/cmd.exe")
    command = _windows_batch_command(["opencode.bat", "hi"])
    assert isinstance(command, str)
    assert command == '"/fake/cmd.exe" /c ""opencode.bat" "hi""'


def test_windows_batch_list_form_is_broken_by_list2cmdline():
    # Regression proof for the laptop round-4 failure: as a list
    # element, list2cmdline backslash-escapes the /c string's quotes,
    # and cmd.exe reads the result as a UNC path ("The network path
    # was not found", exit 1). list2cmdline is pure Python, so this
    # runs on Linux too.
    line = _batch_command_line(["opencode.bat", "hello world"])
    cmdline = subprocess.list2cmdline(["cmd.exe", "/c", line])
    assert '\\"' in cmdline  # backslash-escaped quotes: the UNC trigger


def test_windows_direct_argv_form_is_unsafe():
    # The direct-argv alternative [comspec, "/c", bat, *args] is NOT a
    # fix. With a spaced .bat path list2cmdline quotes it, so the /c
    # string starts with a quote and cmd's /c quote-stripping rule
    # mangles it:
    spaced = subprocess.list2cmdline(
        ["cmd.exe", "/c", "C:\\My Dir\\opencode.bat", "hello"])
    assert spaced.split("/c ", 1)[1].startswith('"')
    # And an arg with a metacharacter but no space (a&b) is passed
    # unquoted, so cmd treats & as a command separator:
    meta = subprocess.list2cmdline(
        ["cmd.exe", "/c", "opencode.bat", "a&b"])
    assert meta.endswith("a&b")  # unquoted: & is live to cmd.exe


def test_write_cli_fake_writes_bat_on_win32(bin_dir, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    script = write_cli_fake(bin_dir, "opencode", "echo hi\n", "@echo hi\n")
    assert script == bin_dir / "opencode.bat"
    assert script.exists()
    assert not (bin_dir / "opencode").exists()
    text = script.read_text(encoding="utf-8")
    assert text.startswith("@echo off")
    assert "@echo hi" in text


def test_write_cli_fake_writes_sh_on_posix(bin_dir, monkeypatch):
    # BUG (laptop round 4): without the platform patch this test reads
    # the real host platform and fails on Windows (writes a .bat).
    monkeypatch.setattr(sys, "platform", "linux")
    script = write_cli_fake(bin_dir, "opencode", "echo hi\n", "@echo hi\n")
    assert script == bin_dir / "opencode"
    assert script.exists()
    assert not (bin_dir / "opencode.bat").exists()
    text = script.read_text(encoding="utf-8")
    assert text.startswith("#!/bin/sh")
    assert "echo hi" in text


def test_windows_bat_stem_allowlist(bin_dir, monkeypatch):
    # On Windows the allowlist is about the binary's STEM: a .bat/.cmd
    # name is allowlisted iff its stem is, and a non-executable suffix
    # is not stripped at all. Both rejections happen before any
    # shutil.which call, so this runs on Linux too (platform patched).
    monkeypatch.setattr(sys, "platform", "win32")
    with pytest.raises(CliProviderError, match="not in the allowlist"):
        _resolve_binary("evil-bin.bat")
    with pytest.raises(CliProviderError, match="not in the allowlist"):
        _resolve_binary("opencode.txt")


@pytest.mark.skipif(sys.platform != "win32",
                    reason="shutil.which PATHEXT needs real Windows: "
                    "its win32 branch calls _winapi, which is None on "
                    "POSIX even with sys.platform patched")
def test_windows_resolve_bare_name_finds_bat_via_pathext(bin_dir, monkeypatch):
    # A bare name resolves to the .bat twin via PATHEXT, still only
    # against the pinned dirs (R-012) -- never the ambient PATH.
    # Runs on the Windows laptop; skipped (not failed) on Linux CI.
    monkeypatch.setenv("PATHEXT",
                       os.pathsep.join([".COM", ".EXE", ".BAT", ".CMD"]))
    write_cli_fake(bin_dir, "opencode", "echo hi\n", "@echo hi\n")
    # BUG (laptop round 4): shutil.which returns the path with the
    # extension cased exactly as in PATHEXT (.BAT), so a plain == with
    # ".bat" fails on real Windows -- compare case-insensitively.
    expected = os.path.normcase(str(bin_dir / "opencode.bat"))
    assert os.path.normcase(_resolve_binary("opencode")) == expected
    # The extension itself is fine too: the allowlist is about the stem.
    assert os.path.normcase(_resolve_binary("opencode.bat")) == expected


def test_windows_resolve_absolute_bat_path(bin_dir, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    script = write_cli_fake(bin_dir, "opencode", "echo hi\n", "@echo hi\n")
    assert _resolve_binary(str(script)) == str(script)
    with pytest.raises(CliProviderError, match="not in the allowlist"):
        _resolve_binary(str(bin_dir / "not-allowed.bat"))


def test_windows_build_argv_wraps_bat_through_cmd(bin_dir, monkeypatch):
    # _build_argv returns a single verbatim command STRING for a .bat
    # provider on win32 (list form breaks under list2cmdline -- see
    # test_windows_batch_list_form_is_broken_by_list2cmdline).
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("COMSPEC", "/fake/cmd.exe")
    script = write_cli_fake(bin_dir, "opencode", "echo hi\n", "@echo hi\n")
    command, temp_path = _build_argv(cli_config(cli_binary=str(script)),
                                     "hello world")
    assert temp_path is None
    assert isinstance(command, str)
    assert command == '"/fake/cmd.exe" /c ' + '"' + f'"{script}" "hello world"' + '"'


def test_windows_run_cli_provider_passes_string_to_subprocess(bin_dir, monkeypatch):
    # End-to-end (mocked subprocess): on win32 a .bat provider reaches
    # subprocess.run as one verbatim string with shell=False -- never
    # as a list, which list2cmdline would mangle (UNC-path failure).
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("COMSPEC", "/fake/cmd.exe")
    script = write_cli_fake(bin_dir, "opencode", "echo hi\n", "@echo hi\n")

    class _FakeProc:
        returncode = 0
        stdout = b"reply\n"
        stderr = b""

    seen = {}

    def _fake_run(args, **kwargs):
        seen["args"] = args
        seen["kwargs"] = kwargs
        return _FakeProc()

    monkeypatch.setattr(subprocess, "run", _fake_run)
    out = run_cli_provider(cli_config(cli_binary=str(script)), "hello world")
    assert out == "reply"
    assert seen["args"] == f'"/fake/cmd.exe" /c ""{script}" "hello world""'
    assert seen["kwargs"]["shell"] is False


def test_windows_fake_preamble_cannot_execute_hostile_args(bin_dir, monkeypatch):
    # The .bat preamble must never strip quotes with percent expansion
    # (%ARGS:"=%) -- that re-exposes & and | to cmd.exe (laptop round 4:
    # `hello & whoami` really executed whoami). Delayed expansion only:
    # the quote-strip and the !ARGS! echo both happen after cmd.exe
    # parses the line, so a metacharacter in an argument stays literal.
    monkeypatch.setattr(sys, "platform", "win32")
    script = write_cli_fake(bin_dir, "opencode", "echo hi\n",
                            "@echo opencode-reply: !ARGS!\n")
    text = script.read_text(encoding="utf-8")
    assert 'set "ARGS=%ARGS:"=%"' not in text
    assert "%ARGS%" not in text
    assert "EnableDelayedExpansion" in text
    assert '!ARGS:"=!' in text  # quote-strip via delayed substitution
    assert "!ARGS!" in text
    # No quotes around ARGS= on the capture line: cmd.exe pairs quotes
    # left-to-right, so `set "ARGS=%*"` with a quoted metachar argument
    # (`"hello & whoami"`) pairs `"ARGS=` with `"hello` and leaves
    # ` & whoami` outside quotes -- whoami really executes (laptop
    # round 5). `set ARGS=%*` keeps the argument's own quotes paired.
    assert "set ARGS=%*\n" in text
    assert 'set "ARGS=%*"' not in text


def test_cli_fake_hostile_arg_is_literal(bin_dir):
    # `hello & whoami` must echo literally and never execute anything.
    # Runs on Linux through the .sh twin and on the Windows laptop
    # through the real .bat under cmd.exe -- same expected output on
    # both, because the preamble strips quotes via delayed expansion.
    write_cli_fake(bin_dir, "opencode", 'printf "opencode-reply: %s\\n" "$*"\n',
                   "@echo opencode-reply: !ARGS!\n")
    out = run_cli_provider(cli_config(), "hello & whoami")
    assert out == "opencode-reply: hello & whoami"


def test_windows_build_argv_leaves_exe_unwrapped(bin_dir, monkeypatch):
    # A real PE executable needs no cmd.exe wrapping.
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("COMSPEC", "/fake/cmd.exe")
    exe = bin_dir / "opencode.exe"
    exe.write_text("fake", encoding="utf-8")
    exe.chmod(0o755)
    argv, temp_path = _build_argv(cli_config(cli_binary=str(exe)),
                                  "hello world")
    assert temp_path is None
    assert argv == [str(exe), "hello world"]
