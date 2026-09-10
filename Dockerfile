# Netwise application image -- Layer 3 (FastAPI) plus Layers 1 and 2's client
# code. US-41 (#333).
#
# WHAT IS AND IS NOT IN HERE
#     This image does NOT contain Batfish and does NOT contain Ollama. Both
#     are separate processes with their own images and their own lifecycles,
#     and `docker-compose.yml` wires them together. Baking them in would make
#     a single image that has to be rebuilt when any one of three things
#     changes, and would hide which component failed when one of them does --
#     which is the distinction `tools/preflight.py` exists to preserve.
#
# WHY THE DEPENDENCIES ARE A SEPARATE LAYER FROM THE SOURCE
#     requirements.txt changes rarely; the source changes constantly. Copying
#     it first means an ordinary code edit reuses the cached pip layer instead
#     of reinstalling pandas every time.
#
# WHY NOT root
#     Netwise reads files a user uploads. If a parser is ever made to write
#     somewhere it should not, the blast radius should not include the whole
#     container filesystem.

FROM python:3.13-slim

# PYTHONDONTWRITEBYTECODE   no .pyc litter in a layer that is thrown away
# PYTHONUNBUFFERED          logs appear in `docker compose logs` immediately
#                           rather than when a buffer happens to flush, which
#                           matters when the thing you are debugging is a hang
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# The dependency layer.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# The source layer. .dockerignore keeps configs/, .venv/ and the documents out
# -- see that file, which is a privacy boundary and not only a size one.
COPY analysis/ ./analysis/
COPY ai/ ./ai/
COPY web/ ./web/
COPY tools/ ./tools/
COPY tests/ ./tests/

# A real network config is never baked into an image. `configs/` is gitignored
# and dockerignored; this is the writable place uploads live at runtime.
RUN mkdir -p /app/configs \
 && useradd --create-home --uid 10001 netwise \
 && chown -R netwise:netwise /app
USER netwise

EXPOSE 8000

# Batfish is a sibling container, not this container's loopback. Overridden by
# docker-compose.yml; named here so the image is runnable on its own.
ENV NETWISE_BATFISH_HOST=batfish

# --host 0.0.0.0 is required: binding loopback inside a container makes the
# port unreachable from the host even when it is published.
CMD ["python", "-m", "uvicorn", "web.main:app", "--host", "0.0.0.0", "--port", "8000"]
