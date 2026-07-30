FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt pyproject.toml ./
COPY hath ./hath
COPY *.py ./

RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir -e .

RUN mkdir -p data cache download log config

EXPOSE 443

HEALTHCHECK --interval=60s --timeout=10s --start-period=120s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('https://127.0.0.1/health', context=__import__('ssl')._create_unverified_context())" || exit 1

CMD ["python", "run_gunicorn.py"]
