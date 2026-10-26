# ProveIt web app: judge mode (precomputed curl reports) and live mode (Nemotron on Nebius Token Factory).
# Keys come from the platform's secrets as env vars: NEBIUS_API_KEY, TAVILY_API_KEY. Never bake them in.
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir uv==0.13.5 \
    && useradd -m -u 1000 user
USER user
WORKDIR /home/user/app
ENV PATH="/home/user/.local/bin:$PATH" UV_LINK_MODE=copy

COPY --chown=user pyproject.toml uv.lock README.md ./
COPY --chown=user src ./src
RUN uv sync --frozen --no-dev

# Live mode reads curl's history at any revision, so it needs a full clone (about 140 MB).
RUN git clone -q https://github.com/curl/curl.git vendor/curl

COPY --chown=user data/demo ./data/demo
# The cross-release symbol index ships prebuilt, so neither the build nor the first live run greps 150 release tags.
COPY --chown=user data/curl_reports.jsonl data/curl_identifier_history.txt ./data/

ENV PROVEIT_FETCH=1 PROVEIT_DAILY_BUDGET=1.00 PROVEIT_RUNS_PER_IP=5 PORT=7860
EXPOSE 7860
CMD ["sh", "-c", "uv run --no-dev uvicorn proveit.web.app:app --host 0.0.0.0 --port ${PORT}"]
