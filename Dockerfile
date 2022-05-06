# Define base images and tags
# ---------------------------
ARG DOCKERFILE_BUILD_IMAGE="docker.io/python"
ARG DOCKERFILE_BUILD_TAG="3.10.0-bullseye"
ARG DOCKERFILE_BASE_IMAGE="docker.io/python"
ARG DOCKERFILE_BASE_TAG="3.10.0-slim-bullseye"


# Prepare venv
# ------------
FROM $DOCKERFILE_BUILD_IMAGE:$DOCKERFILE_BUILD_TAG AS build
WORKDIR "/app"

# Need for caching proxy
ARG PIP_INDEX_URL=https://pypi.org/simple/
ARG PIP_INDEX=https://pypi.org/pypi/

# Install dependecies
# hadolint ignore=DL3015,DL3008,DL3013,DL3042
RUN set -eux && \
    apt-get update && \
    apt-get install --no-install-recommends -y \
        python3-dev gcc libc-dev libev-dev libevdev2 && \
    python -m pip install --no-cache-dir --upgrade --force --ignore-installed pip && \
    pip install --no-cache-dir --upgrade --upgrade-strategy eager wheel && \
    python -m venv .venv

# Install python dependecies
COPY requirements.txt .
ENV PATH "/app/.venv/bin:/app:$PATH"

RUN set -eux && \
    pip install --no-cache-dir --requirement requirements.txt

# Copy scripts
COPY guassp.sh ./guassp
COPY app.py worker.py wsgi.py ./


# Make app image
# --------------
FROM $DOCKERFILE_BUILD_IMAGE:$DOCKERFILE_BUILD_TAG
WORKDIR "/app"

# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install --no-install-recommends -y libev-dev libevdev2 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy components
COPY --from=build /app /app

ENTRYPOINT ["/app/guassp"]
