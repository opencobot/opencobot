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
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # avoid a runtime import cycle with model_gateway
    from .model_gateway import ProviderConfig

# Binary names a provider config may name. Anything else is rejected.
ALLOWED_BINARIES = frozenset({"opencode", "kiro", "gpt", "q", "custom-cli"})

# R-012: trusted directories a bare CLI binary name may resolve from.
# The ambient PATH is never consulted (see _pinned_bin_dirs). These
# defaults are defined here because the scrubbed child environment
# (R-010) also sets PATH to exactly these dirs.
DEFAULT_CLI_BIN_DIRS: tuple[str, ...] = ("/usr/local/bin", "/usr/bin", "/bin")

#: Operator override for the pinned binary dirs: colon-separated,
#: same shape as PATH. Trusted local configuration, like the gateway
#: config file (ADR-007) -- only the machine owner writes it.
CLI_BIN_DIRS_ENV = "OPENCOBOT_CLI_BIN_DIRS"


def _pinned_bin_dirs(config_dirs: tuple[str, ...] | list[str] | None = None) -> tuple[str, ...]:
    """Resolve the pinned binary dirs (R-012).

    Precedence: per-provider ``cli_binary_dirs`` on the ProviderConfig
    > ``OPENCOBOT_CLI_BIN_DIRS`` env var > ``DEFAULT_CLI_BIN_DIRS``.
    The ambient PATH is deliberately never consulted: a fake binary
    planted earlier on PATH must not win over the genuine one.
    """
    if config_dirs:
        return tuple(str(d) for d in config_dirs)
    override = os.environ.get(CLI_BIN_DIRS_ENV)
    if override:
        dirs = tuple(d for d in override.split(os.pathsep) if d)
        if dirs:
            return dirs
    return DEFAULT_CLI_BIN_DIRS

# R-010: the child process environment is built from an allowlist, never
# inherited wholesale. A compromised CLI binary must not be able to read
# ambient credentials (API keys, cloud tokens, ...) from os.environ.
# Only the non-secret variables a CLI plausibly needs to run survive;
# PATH is set to the pinned binary dirs (R-012) so the child's own
# subprocess lookups are constrained too.
CLI_ENV_ALLOWLIST = frozenset({
    "PATH", "HOME", "TMPDIR", "TEMP", "TMP",
    "LANG", "LC_ALL", "LC_CTYPE", "TERM", "USER", "LOGNAME",
})

# Names that look like credentials. Ambient variables matching these are
# dropped even if they ever landed in the allowlist; explicit per-call
# ``env`` overrides (the operator's own config) are passed through
# verbatim, so the operator -- and only the operator -- can hand a CLI
# a key it genuinely needs.
_SECRET_ENV_KEY_RE = re.compile(
    r"(?i)(api[_-]?key|access[_-]?key|secret|token|password|passwd|pwd"
    r"|auth|bearer|private[_-]?key|credentials?|session|cookie"
    r"|aws_|gcp_|azure_|openai_|anthropic_|github_)"
)


def _is_secret_env_key(name: str) -> bool:
    return bool(_SECRET_ENV_KEY_RE.search(name))


# R-011: stderr from a model CLI is untrusted output -- a hostile CLI
# can echo secrets, keys or prompt text into it, and the non-zero-exit
# error used to carry up to 200 chars of that stderr verbatim into
# exceptions (and from there into gateway error results, CLI output
# and logs). Redact anything that looks like a credential before it
# leaves this module; the exit code itself is safe to keep.
_SECRET_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    # key=value / key: value assignments (api_key=..., token: ..., ...)
    re.compile(
        r"(?i)(api[_-]?key|access[_-]?key|secret|token|password|passwd"
        r"|auth|bearer|private[_-]?key|client[_-]?secret)"
        r"(\s*[:=]\s*)([\"']?)([^\s\"',;]+)"
    ),
    # Bearer <token> headers
    re.compile(r"(?i)(bearer\s+)([A-Za-z0-9._\-~+/=]{8,})"),
    # well-known token shapes
    re.compile(r"sk-[A-Za-z0-9_\-]{8,}"),  # OpenAI-style
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}"),  # Anthropic-style
    re.compile(r"(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{8,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{8,}"),  # Slack tokens
    # PEM private key blocks
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
               re.DOTALL),
)


def redact_secrets(text: str) -> str:
    """Replace credential-looking substrings in ``text`` with [REDACTED].

    Applied to CLI stderr before it is put in an exception message, so
    a hostile CLI cannot smuggle a secret into logs or audit via an
    error. Non-secret text passes through unchanged.
    """
    redacted = text
    for pattern in _SECRET_VALUE_PATTERNS:
        if pattern.groups == 4:
            redacted = pattern.sub(r"\1\2\3[REDACTED]", redacted)
        elif pattern.groups == 2:
            redacted = pattern.sub(r"\1[REDACTED]", redacted)
        else:
            redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def _scrubbed_env(env: dict | None, bin_dirs: tuple[str, ...]) -> dict[str, str]:
    """Build the child environment for a CLI provider (R-010).

    Ambient ``os.environ`` contributes only allowlisted, non-secret
    names; PATH is forced to the pinned binary dirs. ``env`` (when
    given) is the caller's explicit per-call override and wins over
    the scrubbed ambient values -- it is how the operator opts a CLI
    into a variable it needs, and how tests point at fake binaries.
    """
    scrubbed: dict[str, str] = {}
    for name in CLI_ENV_ALLOWLIST:
        value = os.environ.get(name)
        if value is not None and not _is_secret_env_key(name):
            scrubbed[name] = value
    # PATH is the pinned binary dirs first, then the default system
    # dirs -- so the CLI can still reach standard tools (sh, sleep,
    # cat, ...) -- and never any ambient PATH entry.
    path_dirs: list[str] = []
    for d in list(bin_dirs) + list(DEFAULT_CLI_BIN_DIRS):
        if d and d not in path_dirs:
            path_dirs.append(d)
    scrubbed["PATH"] = os.pathsep.join(path_dirs)
    if env:
        scrubbed.update({str(k): str(v) for k, v in env.items()})
    return scrubbed

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


def _resolve_binary(binary: str, bin_dirs: tuple[str, ...] | None = None) -> str:
    """Resolve ``binary`` against the allowlist; return an executable path.

    Bare names are looked up ONLY in the pinned binary dirs (R-012:
    per-provider ``cli_binary_dirs`` > ``OPENCOBOT_CLI_BIN_DIRS`` >
    ``DEFAULT_CLI_BIN_DIRS``) -- never on the ambient PATH, so a fake
    binary planted earlier on PATH cannot win. Absolute or relative
    paths are accepted only if their basename is allowlisted and the
    file exists and is executable.
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
    dirs = _pinned_bin_dirs(bin_dirs)
    found = shutil.which(binary, path=os.pathsep.join(dirs))
    if found is None:
        raise CliProviderError(
            f"CLI binary {binary!r} not found in pinned binary dirs "
            f"({os.pathsep.join(dirs)})"
        )
    return found


def _build_argv(
    config: "ProviderConfig", prompt: str, bin_dirs: tuple[str, ...] | None = None
) -> tuple[list[str], str | None]:
    """Build the argv array and the temp-file path (if any) for a call.

    Returns (argv, temp_path). The prompt is substituted only into the
    single "{prompt}" placeholder when ``cli_prompt_via == "arg"``; for
    "file" the placeholder is replaced with a temp-file path holding the
    prompt; for "stdin" the prompt is fed on stdin and never appears in
    argv. The caller must delete ``temp_path`` when set.
    """
    binary = _resolve_binary(config.cli_binary or "", bin_dirs=bin_dirs)
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
    The child runs with a scrubbed environment (R-010: allowlisted
    variables only, PATH pinned to the trusted binary dirs) so ambient
    credentials are never inherited. The returned text is
    untrusted/tainted data -- callers must not execute it or treat it
    as verified fact.
    """
    if config.kind != "cli":
        raise CliProviderError(f"provider {config.name!r} is not a CLI provider")
    # R-012: resolve the binary against the pinned dirs only.
    bin_dirs = _pinned_bin_dirs(getattr(config, "cli_binary_dirs", None))
    argv, temp_path = _build_argv(config, prompt, bin_dirs=bin_dirs)
    try:
        # R-010: the child gets a scrubbed environment (allowlist only),
        # never the ambient os.environ with its API keys and tokens.
        run_env = _scrubbed_env(env, bin_dirs)
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
            # R-011: stderr is untrusted CLI output -- redact anything
            # credential-looking before it enters the exception (and
            # from there gateway error results and logs).
            detail = f": {redact_secrets(stderr)[:200]}" if stderr else ""
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
