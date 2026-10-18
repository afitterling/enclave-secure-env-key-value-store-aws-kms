# Init image for the enclave-envoy cloud runner (built by `sst deploy` when
# features.cloudRunner is on). It runs `enclave runner-init` as the first,
# non-essential container of every run: proves the task's IAM role, fetches
# that run's secrets in memory and writes them to the task's ephemeral volume.
# The app container depends on this exiting 0.
#
# Pinned by digest (multi-arch index of python:3.12-slim, resolved 2026-10-19)
# so a moved tag cannot change the image that handles every run's plaintext.
# Bump deliberately: `docker buildx imagetools inspect python:3.12-slim`.
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /src
COPY pyproject.toml ./
COPY enclave ./enclave
RUN pip install --no-cache-dir ".[aws]" && rm -rf /src

WORKDIR /
# Image default only. Fargate bind-mount volumes start root-owned, so the task
# definition runs this container as uid 0 with every capability dropped except
# CHOWN, and passes `--owner <app uid:gid>`: the files end up 0400 in a 0700
# dir owned by the app's user. No VOLUME here; the task definition mounts one.
USER 65534:65534
ENTRYPOINT ["enclave"]
CMD ["runner-init"]
