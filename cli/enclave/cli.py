"""`enclave` command-line interface."""

from __future__ import annotations

import glob as globmod
import os
import sys
from pathlib import Path

import click

from enclave import auth, container, sync, workload
from enclave.client import ApiClient, ApiError
from enclave.config import Config, Session

# `exec`/`run` take the wrapped command after `--`; its own flags must reach it untouched.
_PASSTHROUGH = {"ignore_unknown_options": True, "allow_interspersed_args": False}


def _client(require_auth: bool = True) -> ApiClient:
    cfg = Config.load()
    session = Session.load()
    token = session.require_token() if require_auth else None
    return ApiClient(cfg.require_api_url(), token=token)


@click.group()
@click.version_option(package_name="enclave-envoy")
def main() -> None:
    """Securely sync dotfiles across devices (AWS S3 + KMS)."""


@main.command()
@click.option("--api-url", required=True, help="HTTPS API URL printed by `sst deploy`.")
def configure(api_url: str) -> None:
    """Store the API endpoint locally."""
    cfg = Config.load()
    cfg.api_url = api_url
    cfg.save()
    click.echo(f"Saved API URL: {api_url}")


@main.command()
@click.argument("email")
@click.option("--code", default=None, help="Skip the prompt by passing the emailed code.")
def login(email: str, code: str | None) -> None:
    """Log in with EMAIL via a one-time code."""
    api = ApiClient(Config.load().require_api_url())
    try:
        session = auth.login(api, email, code)
    except ApiError as e:
        raise SystemExit(f"Login failed: {e}")
    projects = ", ".join(session.access) or "(none)"
    click.echo(f"Logged in as {session.email}. Projects: {projects}")


@main.command(name="machine-login")
@click.option("--project", required=True)
@click.option("--identity", required=True, help="Machine identity id configured on the project.")
@click.option("--github", is_flag=True, help="Use the GitHub Actions OIDC token.")
@click.option("--oidc-token-file", default=None, help="Read an OIDC JWT from this file.")
@click.option("--oidc-token-env", default=None, help="Read an OIDC JWT from this environment variable.")
@click.option("--aws", "use_aws", is_flag=True, help="Prove the ambient AWS IAM role (signed STS).")
@click.option("--audience", default=None, help="Override the audience the server advertises.")
@click.option("--print-token", is_flag=True, help="Print only the token instead of saving a session.")
def machine_login(
    project: str,
    identity: str,
    github: bool,
    oidc_token_file: str | None,
    oidc_token_env: str | None,
    use_aws: bool,
    audience: str | None,
    print_token: bool,
) -> None:
    """Log a workload in with its platform identity (no OTP, no stored secret)."""
    api = ApiClient(Config.load().require_api_url())
    try:
        result = workload.login(
            api,
            project,
            identity,
            github=github,
            token_file=oidc_token_file,
            token_env=oidc_token_env,
            aws=use_aws,
            audience=audience,
        )
    except (ApiError, workload.WorkloadError, OSError) as e:
        raise SystemExit(f"Machine login failed: {e}")
    if print_token:
        click.echo(result["token"])
        return
    Session(
        email=result["principal"],
        token=result["token"],
        access={result["project"]: result.get("stages", [])},
    ).save()
    click.echo(
        f"Logged in as {result['principal']} ({result.get('access', 'read')} on "
        f"{', '.join(result.get('stages', [])) or 'no stages'}), valid {result.get('expiresIn', '?')}s."
    )


@main.command()
def logout() -> None:
    """Forget the local session."""
    Session.load().clear()
    click.echo("Logged out.")


@main.command()
def whoami() -> None:
    """Show the current user and access map (server-validated)."""
    try:
        info = _client().whoami()
    except ApiError as e:
        raise SystemExit(str(e))
    click.echo(f"Email: {info['email']}")
    for project, stages in info.get("access", {}).items():
        click.echo(f"  {project}: {', '.join(stages)}")


@main.command(name="list")
@click.option("--project", required=True)
@click.option("--stage", required=True)
def list_cmd(project: str, stage: str) -> None:
    """List files stored for a project/stage."""
    try:
        files = sync.remote_list(_client(), project, stage)
    except ApiError as e:
        raise SystemExit(str(e))
    if not files:
        click.echo("(empty)")
    for f in files:
        click.echo(f)


@main.command()
@click.option("--project", required=True)
@click.option("--stage", required=True)
@click.option("--glob", "glob_pat", default=None, help="Glob of files to push, e.g. '$HOME/.*'.")
@click.argument("files", nargs=-1, type=click.Path(exists=True, dir_okay=False, path_type=Path))
def push(project: str, stage: str, glob_pat: str | None, files: tuple[Path, ...]) -> None:
    """Encrypt and upload FILES (and/or a --glob) to project/stage."""
    targets = list(files)
    if glob_pat:
        targets += [Path(p) for p in globmod.glob(globmod.os.path.expanduser(glob_pat)) if Path(p).is_file()]
    if not targets:
        raise SystemExit("Nothing to push. Pass files or --glob.")

    api = _client()
    for path in targets:
        try:
            key = sync.push_file(api, project, stage, path)
            click.echo(f"↑ {path}  →  s3://{key}")
        except (ApiError, OSError) as e:
            click.echo(f"✗ {path}: {e}", err=True)


@main.command()
@click.option("--project", required=True)
@click.option("--stage", required=True)
@click.option("--dest", default=".", type=click.Path(file_okay=False, path_type=Path), help="Destination directory.")
@click.option("--only", multiple=True, help="Restrict to specific file names (repeatable).")
def pull(project: str, stage: str, dest: Path, only: tuple[str, ...]) -> None:
    """Download and decrypt files from project/stage into --dest."""
    api = _client()
    try:
        files = list(only) if only else sync.remote_list(api, project, stage)
    except ApiError as e:
        raise SystemExit(str(e))
    if not files:
        click.echo("(nothing to pull)")
        return
    for name in files:
        try:
            out = sync.pull_file(api, project, stage, name, dest)
            click.echo(f"↓ {name}  →  {out}")
        except (ApiError, OSError) as e:
            click.echo(f"✗ {name}: {e}", err=True)


def _load_secrets(project: str, stage: str, files: tuple[str, ...]) -> dict:
    try:
        secrets, used = sync.load_env(_client(), project, stage, list(files) or None)
    except (ApiError, OSError, ValueError, UnicodeDecodeError) as e:
        raise SystemExit(f"Could not load secrets: {e}")
    if not used:
        raise SystemExit(f"No env files in {project}/{stage}. Pass --file NAME.")
    names = container.usable_secret_names(secrets)
    for skipped in sorted(set(secrets) - set(names)):
        click.echo(f"warning: skipping {skipped!r}: not a valid environment variable name", err=True)
    return {k: secrets[k] for k in names}


@main.command(name="exec", context_settings=_PASSTHROUGH)
@click.option("-p", "--project", required=True)
@click.option("-s", "--stage", required=True)
@click.option("--file", "files", multiple=True, help="Env file to load (repeatable; default: all .env files).")
@click.option("--override/--no-override", default=True, help="Secrets beat existing environment variables.")
@click.argument("cmd", nargs=-1, required=True, type=click.UNPROCESSED)
def exec_cmd(project: str, stage: str, files: tuple[str, ...], override: bool, cmd: tuple[str, ...]) -> None:
    """Run CMD with the stage's secrets in its environment. Nothing is written to disk."""
    secrets = _load_secrets(project, stage, files)
    env = dict(os.environ)
    for key, value in secrets.items():
        if override or key not in env:
            env[key] = value
    try:
        code = container.run_forwarding_signals(list(cmd), env)
    except FileNotFoundError:
        raise SystemExit(f"command not found: {cmd[0]}")
    sys.exit(code)


@main.command(context_settings=_PASSTHROUGH)
@click.option("-p", "--project", required=True)
@click.option("-s", "--stage", required=True)
@click.option("--file", "files", multiple=True, help="Env file to load (repeatable; default: all .env files).")
@click.option("--engine", type=click.Choice(["docker", "podman"]), default=None)
@click.option("--as-files", is_flag=True, help=f"Mount secrets as files at {container.SECRETS_MOUNT} instead of env.")
@click.option("--network", default="bridge", show_default=True, help="bridge, none, or a named network (not host).")
@click.option("--publish", multiple=True, help="Port mapping, as for docker run -p (repeatable).")
@click.option("--volume", "volumes", multiple=True, help="SRC:DST[:ro|rw], read-only by default (repeatable).")
@click.option("--env", "env_pairs", multiple=True, help="Non-secret KEY=VALUE (repeatable).")
@click.option("--user", default="65534:65534", show_default=True)
@click.option("--memory", default="512m", show_default=True)
@click.option("--cpus", default=None)
@click.option("--pids-limit", default=256, show_default=True, type=int)
@click.option("--writable", is_flag=True, help="Allow writes to the root filesystem (drops --read-only).")
@click.option("--cap-add", multiple=True, help=f"One of {', '.join(sorted(container.CAP_ALLOWLIST))}.")
@click.option("--allow-unpinned", is_flag=True, help="Run an image that is not pinned by @sha256 digest.")
@click.option("--cosign-key", default=None, type=click.Path(exists=True, dir_okay=False))
@click.option("--workdir", default=None)
@click.option("--entrypoint", default=None)
@click.option("--dry-run", is_flag=True, help="Print the engine command (secret names only) and exit.")
@click.argument("image")
@click.argument("cmd", nargs=-1, type=click.UNPROCESSED)
def run(
    project: str,
    stage: str,
    files: tuple[str, ...],
    engine: str | None,
    as_files: bool,
    network: str,
    publish: tuple[str, ...],
    volumes: tuple[str, ...],
    env_pairs: tuple[str, ...],
    user: str,
    memory: str,
    cpus: str | None,
    pids_limit: int,
    writable: bool,
    cap_add: tuple[str, ...],
    allow_unpinned: bool,
    cosign_key: str | None,
    workdir: str | None,
    entrypoint: str | None,
    dry_run: bool,
    image: str,
    cmd: tuple[str, ...],
) -> None:
    """Run IMAGE in a hardened container with the stage's secrets.

    \b
    Always applied: --rm --init --read-only --cap-drop ALL
    --security-opt no-new-privileges --ipc private, a noexec /tmp tmpfs,
    a non-root user, and pids/memory limits.
    """
    opts = container.RunOptions(
        image=image,
        command=list(cmd),
        network=network,
        publish=list(publish),
        volumes=list(volumes),
        env=list(env_pairs),
        user=user,
        memory=memory,
        cpus=cpus,
        pids_limit=pids_limit,
        writable=writable,
        cap_add=list(cap_add),
        workdir=workdir,
        entrypoint=entrypoint,
    )
    if not container.is_pinned(image):
        if not allow_unpinned:
            raise SystemExit(
                f"{image} is not pinned by digest. Use IMAGE@sha256:<digest>, or --allow-unpinned."
            )
        click.echo(f"warning: {image} is not pinned by digest; a moved tag changes what runs", err=True)
    try:
        # Validate everything before any secret is fetched.
        container.build_argv("engine", opts, [])
    except container.UnsafeOption as e:
        raise SystemExit(str(e))

    secrets = _load_secrets(project, stage, files)
    names = list(secrets)

    if dry_run:
        mount = "<secrets-dir>" if as_files else None
        if as_files and click.get_current_context().get_parameter_source("user") == click.core.ParameterSource.DEFAULT:
            opts.user = f"{os.getuid()}:{os.getgid()}" if os.geteuid() else opts.user
        click.echo(" ".join(container.build_argv(engine or "docker", opts, names, mount)))
        return

    try:
        eng = container.detect_engine(engine)
        if cosign_key:
            container.cosign_verify(image, cosign_key)
    except RuntimeError as e:
        raise SystemExit(str(e))

    secrets_dir = None
    try:
        if as_files:
            explicit = click.get_current_context().get_parameter_source("user") != click.core.ParameterSource.DEFAULT
            opts.user, opts.userns_keep_id, chown_to = container.files_user(eng, user if explicit else None)
            if explicit:
                click.echo(f"note: --user {user} must be able to read files owned by uid {os.getuid()}", err=True)
            secrets_dir = container.write_secrets_dir(secrets, names, container.warn, chown_to)
            child = container.child_env({}, [])
        else:
            click.echo(
                "note: env values are visible to `docker inspect` on this host; --as-files avoids that",
                err=True,
            )
            child = container.child_env(secrets, names)
        argv = container.build_argv(eng, opts, names, secrets_dir)
        code = container.run_forwarding_signals(
            argv, child, on_exit=lambda: container.remove_secrets_dir(secrets_dir)
        )
    finally:
        container.remove_secrets_dir(secrets_dir)
    sys.exit(code)


if __name__ == "__main__":
    main()
