FROM python:3.14-trixie

# Set timezone
ENV TZ=Europe/Moscow
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# UV installation
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /uvx /bin/
ENV UV_PROJECT_ENVIRONMENT="/usr/local/"
# Install dependencies
# COPY pyproject.toml uv.lock /tmp/uv/
# RUN uv sync --no-cache --all-groups --project /tmp/uv && rm -rf /tmp/uv/

# Set `DEVCONTAINER` environment variable to help with orientation
ENV DEVCONTAINER=true