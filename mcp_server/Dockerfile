# Hunt Console MCP server - container image
#
# Build from the repository root:
#   docker build -f mcp_server/Dockerfile -t huntconsole-mcp:1.2.0 .
#
# Run it from your MCP client with the hardened flags shown in
# mcp_server/examples/claude_desktop_config.docker.json:
#   --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges
#   and the folder you want readable mounted read-only at /data.
#
# Design:
#   * Base image pinned by digest (python:3.13-slim, digest from
#     docker-library/repo-info on 2026-10-28). Update it deliberately.
#   * No pip, no build step, no packages fetched: the server is standard
#     library only, so the source is copied in and run as-is. Nothing
#     downloaded at build time means nothing to tamper with in transit.
#   * Code is owned by root and read-only to the runtime user; the server
#     runs as an unprivileged user with no home directory and no shell.

FROM python:3.13-slim@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb

RUN groupadd --system --gid 10001 hunt \
 && useradd --system --uid 10001 --gid hunt --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin hunt

WORKDIR /app
COPY cli.py ./
COPY backends/ backends/
COPY connectors/ connectors/
COPY cve_hunt/ cve_hunt/
COPY explanation/ explanation/
COPY ir/ ir/
COPY manual_input/ manual_input/
COPY parser/ parser/
COPY report_parser/ report_parser/
COPY mcp_server/ mcp_server/

# Strip test suites from the image and make the code read-only.
RUN find /app -type d -name tests -prune -exec rm -rf {} + \
 && find /app -type d -name __pycache__ -prune -exec rm -rf {} + \
 && chmod -R a-w,a+rX /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 10001:10001

LABEL org.opencontainers.image.title="huntconsole-mcp" \
      org.opencontainers.image.version="1.2.0" \
      org.opencontainers.image.description="Hunt Console MCP server (stdio, read-only, offline)"

# -E ignores PYTHON* environment variables, -s ignores the user site directory.
ENTRYPOINT ["python", "-E", "-s", "-m", "mcp_server"]
