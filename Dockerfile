# syntax=docker/dockerfile:1
# Ảnh chạy ghidra_auto.py (Ghidra headless + PyGhidra), user non-root.

# Base ghim theo digest (index đa kiến trúc), tra từ Docker Hub ngày 2026-10-05.
ARG BASE_IMAGE=python:3.13-slim-trixie@sha256:3dd7cc108ec1493442514f5c2a871af6af0ec31d768ff6e378a93340c3b3db5f

# ---------- Stage 1: tải và giải nén Ghidra (curl/unzip không vào ảnh cuối) ----------
FROM ${BASE_IMAGE} AS ghidra
# Lấy thông tin từ GitHub release của NSA Ghidra (Ghidra_12.1.4_build)
ARG GHIDRA_VERSION="12.1.4"
ARG GHIDRA_DATE="20260921"
ARG GHIDRA_SHA256="ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db"
RUN set -eu; \
    if [ -z "$GHIDRA_VERSION" ] || [ -z "$GHIDRA_DATE" ] || [ -z "$GHIDRA_SHA256" ]; then \
      echo "Thiếu GHIDRA_VERSION / GHIDRA_DATE / GHIDRA_SHA256 (xem TODO trong Dockerfile)" >&2; exit 1; \
    fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl unzip; \
    zip="ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip"; \
    curl -fsSL -o "/tmp/$zip" \
      "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/$zip"; \
    echo "${GHIDRA_SHA256}  /tmp/$zip" | sha256sum -c -; \
    unzip -q "/tmp/$zip" -d /tmp; \
    mv "/tmp/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/ghidra; \
    test -f /opt/ghidra/Ghidra/Features/PyGhidra/lib/PyGhidra.jar

# ---------- Stage 2: ảnh chạy ----------
FROM ${BASE_IMAGE}

# Ghidra 12.x cần JDK 21; libstdc++6 cho bộ decompiler native.
# ARG CACHE_DATE được workflow truyền vào khi chạy theo lịch (schedule)
# để buộc layer này không dùng cache, đảm bảo apt-get upgrade thật sự chạy.
ARG CACHE_DATE=cached
RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends openjdk-21-jdk-headless libstdc++6 \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip setuptools \
 && pip install --no-cache-dir --upgrade -r /app/requirements.txt

COPY --from=ghidra /opt/ghidra /opt/ghidra
COPY ghidra_auto.py find_candidates.py pcode_analysis.py debug_pcode.py /app/

# User non-root; thư mục project Ghidra phải ghi được (binary có thể mount read-only).
RUN useradd --create-home --uid 10001 app \
 && mkdir -p /home/app/projects \
 && chown app:app /home/app/projects

ENV GHIDRA_INSTALL_DIR=/opt/ghidra \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER app
WORKDIR /home/app

# Luôn truyền --project-dir để PyGhidra không tạo project cạnh binary.
ENTRYPOINT ["python3", "/app/ghidra_auto.py", "--project-dir", "/home/app/projects"]
CMD ["--help"]
