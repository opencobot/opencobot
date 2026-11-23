"""Tests for core/cli_providers.py. No real CLIs: fake executable
scripts on a monkeypatched PATH stand in for opencode / q / gpt."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from core.cli_providers import (  # noqa: E402
    ALLOWED_BINARIES,
    BUILTIN_CLI_PROVIDERS,
    CliProviderError,
    builtin_cli_config,
    run_cli_provider,
)
from core.model_gateway import ProviderConfig  # noqa: E402


def write_script(bin_dir: Path, name: str, body: str) -> Path:
    path = bin_dir / name
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(0o755)
    return path


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
    write_script(bin_dir, "opencode", 'printf "opencode-reply: %s\\n" "$*"\n')
    out = run_cli_provider(cli_config(), "hello world")
    assert out == "opencode-reply: hello world"


def test_gpt_fake_script_stdin_mode(bin_dir):
    write_script(bin_dir, "gpt", 'printf "stdin:"; cat; printf "\\n"\n')
    cfg = cli_config("gpt", cli_prompt_via="stdin")
    out = run_cli_provider(cfg, "read me from stdin")
    assert out == "stdin:read me from stdin"


def test_q_fake_script_json_field_output(bin_dir):
    write_script(bin_dir, "q", 'printf "{\\"text\\": \\"q-json-reply\\"}\\n"\n')
    cfg = cli_config("q", cli_output="json-field", cli_output_field="text")
    assert run_cli_provider(cfg, "anything") == "q-json-reply"


def test_prompt_via_file(bin_dir):
    write_script(bin_dir, "opencode", 'cat "$@"\n')
    cfg = cli_config(cli_prompt_via="file")
    assert run_cli_provider(cfg, "prompt from file") == "prompt from file"


def test_custom_cli_template(bin_dir):
    write_script(bin_dir, "custom-cli", 'printf "custom:%s\\n" "$*"\n')
    cfg = cli_config(
        "custom-cli",
        cli_argv_template=["answer", "--mode", "fast", "{prompt}"],
    )
    assert run_cli_provider(cfg, "hi") == "custom:answer --mode fast hi"


def test_stdin_prompt_never_appears_in_argv(bin_dir):
    # The script echoes its argv; the prompt must not be among them.
    write_script(bin_dir, "gpt", 'printf "argv:%s\\n" "$*"\n')
    cfg = cli_config("gpt", cli_prompt_via="stdin",
                     cli_argv_template=["run"])
    out = run_cli_provider(cfg, "top-secret-prompt")
    assert out == "argv:run"
    assert "top-secret-prompt" not in out


# ---------------------------------------------------------------- failures

def test_timeout_raises(bin_dir):
    write_script(bin_dir, "opencode", "sleep 10\n")
    with pytest.raises(CliProviderError, match="timed out"):
        run_cli_provider(cli_config(), "hi", timeout=1)


def test_nonzero_exit_raises_with_stderr(bin_dir):
    write_script(bin_dir, "opencode", 'echo "boom stderr" >&2\nexit 3\n')
    with pytest.raises(CliProviderError, match="exited with code 3"):
        run_cli_provider(cli_config(), "hi")


def test_bad_json_raises(bin_dir):
    write_script(bin_dir, "q", 'echo "not json{"\n')
    cfg = cli_config("q", cli_output="json-field")
    with pytest.raises(CliProviderError, match="invalid JSON"):
        run_cli_provider(cfg, "hi")


def test_json_missing_text_field_raises(bin_dir):
    write_script(bin_dir, "q", 'printf "{\\"other\\": 1}\\n"\n')
    cfg = cli_config("q", cli_output="json-field")
    with pytest.raises(CliProviderError, match="no text field"):
        run_cli_provider(cfg, "hi")


def test_empty_output_raises(bin_dir):
    write_script(bin_dir, "opencode", "true\n")
    with pytest.raises(CliProviderError, match="empty output"):
        run_cli_provider(cli_config(), "hi")


def test_non_cli_kind_rejected(bin_dir):
    cfg = ProviderConfig("ollama-local", "ollama", "http://localhost:11434", "llama3.1")
    with pytest.raises(CliProviderError, match="not a CLI provider"):
        run_cli_provider(cfg, "hi")


# ---------------------------------------------------------------- safety

def test_shell_metacharacters_treated_as_data(bin_dir, tmp_path):
    write_script(bin_dir, "opencode", 'printf "got:%s\\n" "$*"\n')
    marker = tmp_path / "pwned"
    prompt = f"$(touch {marker}); `touch {marker}.2`; hello"
    out = run_cli_provider(cli_config(), prompt)
    assert "$(touch" in out
    assert not marker.exists()
    assert not Path(str(marker) + ".2").exists()


def test_binary_not_in_allowlist_rejected(bin_dir):
    write_script(bin_dir, "evil-bin", 'echo hi\n')
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
    script = write_script(bin_dir, "opencode", 'printf "abs:%s\\n" "$*"\n')
    cfg = cli_config(cli_binary=str(script))
    assert run_cli_provider(cfg, "hi") == "abs:hi"


def test_absolute_path_binary_with_other_basename_rejected(bin_dir):
    script = write_script(bin_dir, "not-allowed", 'echo hi\n')
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
