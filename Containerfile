# syntax=docker/dockerfile:1
FROM python:3.12-slim AS builder
WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim
RUN useradd --create-home --uid 10001 vheatm
COPY --from=builder /install /usr/local
USER vheatm
WORKDIR /workspace
ENTRYPOINT ["vheatm-validate"]
CMD ["--root", "/workspace"]
