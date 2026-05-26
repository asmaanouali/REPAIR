# IR-SAM Artifact -- Dockerfile
#
# Single-stage image kept deliberately small. Reproducing the headline
# numbers requires only Python 3.10 + the project pip-installable
# dependencies; no JVM, no GPU, no network at run-time.
#
# Build:
#     docker build -t irsam:v1.0 -f artifact/Dockerfile .
# Smoke (≤30 minutes on a 4-core/8GB laptop):
#     docker run --rm irsam:v1.0 bash /opt/irsam/artifact/smoke_test.sh
# Full re-run:
#     docker run --rm irsam:v1.0 bash /opt/irsam/artifact/full_run.sh

FROM python:3.10-slim-bookworm

LABEL org.opencontainers.image.title="IR-SAM artifact" \
      org.opencontainers.image.description="Interpreter-aware sound \
repair of injection vulnerabilities -- reproducibility artifact." \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://example.org/anonymous" \
      org.opencontainers.image.version="1.0.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# System deps. Kept to a minimum so the image stays well under 500 MB.
RUN apt-get update && apt-get install -y --no-install-recommends \
      bash curl ca-certificates git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/irsam

# Install Python deps first to maximise layer cache reuse.
COPY ir-sam/pyproject.toml /opt/irsam/ir-sam/pyproject.toml
COPY artifact/requirements.txt /opt/irsam/artifact/requirements.txt
RUN pip install -r /opt/irsam/artifact/requirements.txt

# Copy the full project.
COPY ir-sam/    /opt/irsam/ir-sam/
COPY paper/     /opt/irsam/paper/
COPY artifact/  /opt/irsam/artifact/
COPY build_phase2_pdf.py build_phase3_paper.py build_phase4_pdf.py \
     build_phase5_pdf.py build_phase6_pdf.py /opt/irsam/

# Provide a non-root user for the smoke-test (ACM Reusable preference).
RUN useradd -m -u 1001 irsam && chown -R irsam /opt/irsam
USER irsam

ENV PYTHONPATH=/opt/irsam/ir-sam

CMD ["bash", "/opt/irsam/artifact/smoke_test.sh"]
