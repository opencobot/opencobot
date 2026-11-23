"""Generic subprocess model providers (SPEC.md section 8.1, Phase 2).

Any AI that runs as a CLI -- opencode, kiro-cli, gpt, Amazon Q CLI,
or a user-supplied ``custom-cli`` -- can be a gateway provider. The
prompt is passed as *data* (stdin, a single argv element, or a temp
file), never through a shell, so shell metacharacters in a prompt or in
model output cannot execute anything.

Safety rules (repo AGENTS.md rule 6, SECURITY.md):
  * argv arrays only -- ``shell`` is never True and commands are never
    built by string concatenation.
  * The binary comes from the provider config's allowlist only, never
    from model output or tool results. A bare name must be in
    ``ALLOWED_BINARIES``; an absolute path is accepted only when its
    basename is allowlisted and the file is executable.
  * CLI output is untrusted, tainted data: it is returned as text for
    the gateway/verifier to check, never executed or trusted as fact.

No secrets are read, stored or logged here.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # avoid a runtime import cycle with model_gateway
    from .model_gateway import ProviderConfig

# Binary names a provider config may name. Anything else is rejected.
ALLOWED_BINARIES = frozenset({"opencode", "kiro", "gpt", "q", "custom-cli"})

# Built-in provider definitions: binary, argv template (args after the
# binary; "{prompt}" is the placeholder), how the prompt is delivered,
# how output is extracted, and whether the CLI sends data off-machine.
# These are defaults -- a user may override any field in their config.
# "q" (Amazon Q CLI) is cloud-backed: it calls AWS, so secret data must
# never be routed to it; the gateway enforces that via ``egress``.
BUILTIN_CLI_PROVIDERS: dict[str, dict] = {
    "opencode": {
        "cli_binary": "opencode",
        "cli_argv_template": ["run", "{prompt}"],
        "cli_prompt_via": "arg",
        "cli_output": "stdout",
        "egress": "local-only",
    },
    "kiro": {
        "cli_binary": "kiro",
        "cli_argv_template": ["chat", "--no-interactive", "{prompt}"],
        "cli_prompt_via": "arg",
        "cli_output": "stdout",
        "egress": "local-only",
    },
    "gpt": {
        "cli_binary": "gpt",
        "cli_argv_template": ["{prompt}"],
        "cli_prompt_via": "arg",
        "cli_output": "stdout",
        "egress": "local-only",
    },
    "q": {
        "cli_binary": "q",
        "cli_argv_template": ["chat", "--no-interactive", "{prompt}"],
        "cli_prompt_via": "arg",
        "cli_output": "stdout",
        "egress": "cloud-backed",
    },
    "custom-cli": {
        "cli_binary": "custom-cli",
        "cli_argv_template": ["{prompt}"],
        "cli_prompt_via": "arg",
        "cli_output": "stdout",
        "egress": "local-only",
    },
}


class CliProviderError(Exception):
    """The CLI provider could not produce output (timeout, exit, bad output)."""


def builtin_cli_config(name: str, **overrides) -> "ProviderConfig":
    """Build a ProviderConfig for a built-in CLI provider.

    ``overrides`` may set any ProviderConfig field (e.g. a custom
    ``cli_argv_template`` or ``cost_per_call``). Unknown names raise
    ValueError.
    """
    from .model_gateway import ProviderConfig

    if name not in BUILTIN_CLI_PROVIDERS:
        raise ValueError(f"unknown built-in CLI provider: {name!r}")
    fields = dict(BUILTIN_CLI_PROVIDERS[name])
    fields.update(overrides)
    return ProviderConfig(
        name=name,
        kind="cli",
        base_url="",
        model=name,
        cli_binary=fields.pop("cli_binary"),
        cli_argv_template=fields.pop("cli_argv_template"),
        cli_prompt_via=fields.pop("cli_prompt_via"),
        cli_output=fields.pop("cli_output"),
        egress=fields.pop("egress"),
        **fields,
    )


def _resolve_binary(binary: str, env: dict | None = None) -> str:
    """Resolve ``binary`` against the allowlist; return an executable path.

    Bare names are looked up on PATH (``env`` overrides the environment
    for the lookup, which is how tests point at fake scripts). Absolute
    or relative paths are accepted only if their basename is allowlisted
    and the file exists and is executable.
    """
    if not binary or not isinstance(binary, str):
        raise CliProviderError("CLI provider has no binary configured")
    name = Path(binary).name
    if name not in ALLOWED_BINARIES:
        raise CliProviderError(
            f"CLI binary {binary!r} is not in the allowlist "
            f"({sorted(ALLOWED_BINARIES)})"
        )
    if os.sep in binary or (os.altsep and os.altsep in binary):
        path = Path(binary)
        if not path.is_file() or not os.access(path, os.X_OK):
            raise CliProviderError(f"CLI binary {binary!r} is not executable")
        return str(path)
    search_path = (env or {}).get("PATH", os.environ.get("PATH", ""))
    found = shutil.which(binary, path=search_path or None)
    if found is None:
        raise CliProviderError(f"CLI binary {binary!r} not found on PATH")
    return found


def _build_argv(
    config: "ProviderConfig", prompt: str, env: dict | None = None
) -> tuple[list[str], str | None]:
    """Build the argv array and the temp-file path (if any) for a call.

    Returns (argv, temp_path). The prompt is substituted only into the
    single "{prompt}" placeholder when ``cli_prompt_via == "arg"``; for
    "file" the placeholder is replaced with a temp-file path holding the
    prompt; for "stdin" the prompt is fed on stdin and never appears in
    argv. The caller must delete ``temp_path`` when set.
    """
    binary = _resolve_binary(config.cli_binary or "", env=env)
    template = list(config.cli_argv_template or ["{prompt}"])
    via = config.cli_prompt_via or "arg"
    if via not in ("stdin", "arg", "file"):
        raise CliProviderError(f"unsupported cli_prompt_via: {via!r}")
    if via == "file":
        fd, temp_path = tempfile.mkstemp(prefix="opencobot-prompt-", suffix=".txt")
        try:
            os.write(fd, prompt.encode("utf-8"))
        finally:
            os.close(fd)
        argv = [binary] + [item.replace("{prompt}", temp_path) for item in template]
        return argv, temp_path
    if via == "arg":
        argv = [binary] + [item.replace("{prompt}", prompt) for item in template]
        return argv, None
    # stdin: prompt never appears in argv, even if the template names it.
    argv = [binary] + [item for item in template if "{prompt}" not in item]
    return argv, None


def _extract_output(config: "ProviderConfig", stdout: str) -> str:
    """Extract the model text from CLI stdout (raw or a JSON field)."""
    mode = config.cli_output or "stdout"
    text = stdout.strip()
    if not text:
        raise CliProviderError("CLI provider produced empty output")
    if mode == "stdout":
        return text
    if mode == "json-field":
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise CliProviderError(f"CLI provider returned invalid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise CliProviderError("CLI provider JSON output is not an object")
        field = config.cli_output_field or "text"
        value = data.get(field)
        if not isinstance(value, str) or not value.strip():
            raise CliProviderError(f"CLI provider JSON output has no text field {field!r}")
        return value.strip()
    raise CliProviderError(f"unsupported cli_output: {mode!r}")


def run_cli_provider(
    config: "ProviderConfig",
    prompt: str,
    timeout: int = 60,
    env: dict | None = None,
) -> str:
    """Run a CLI provider once and return its output text.

    ``config`` supplies the allowlisted binary, argv template, prompt
    delivery and output extraction (see ``ProviderConfig``). ``timeout``
    bounds the run; a timeout or non-zero exit raises CliProviderError.
    The returned text is untrusted/tainted data -- callers must not
    execute it or treat it as verified fact.
    """
    if config.kind != "cli":
        raise CliProviderError(f"provider {config.name!r} is not a CLI provider")
    argv, temp_path = _build_argv(config, prompt, env=env)
    try:
        run_env = dict(os.environ)
        if env:
            run_env.update(env)
        try:
            proc = subprocess.run(
                argv,
                input=prompt.encode("utf-8") if config.cli_prompt_via == "stdin" else None,
                capture_output=True,
                timeout=timeout,
                shell=False,  # never a shell: argv array only
                env=run_env,
            )
        except subprocess.TimeoutExpired as exc:
            raise CliProviderError(
                f"CLI provider {config.name!r} timed out after {timeout}s"
            ) from exc
        except OSError as exc:
            raise CliProviderError(f"could not run CLI provider {config.name!r}: {exc}") from exc
        if proc.returncode != 0:
            stderr = proc.stderr.decode("utf-8", "replace").strip()
            detail = f": {stderr[:200]}" if stderr else ""
            raise CliProviderError(
                f"CLI provider {config.name!r} exited with code {proc.returncode}{detail}"
            )
        return _extract_output(config, proc.stdout.decode("utf-8", "replace"))
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
