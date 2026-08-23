FROM python:3.12-slim

LABEL org.opencontainers.image.title="SAST-VULN-SCANNER"
LABEL org.opencontainers.image.description="Next-Gen AI-Powered Universal SAST Agent"
LABEL org.opencontainers.image.source="https://github.com/walimuhamad185/SAST-VULN-SCANNER"

WORKDIR /app
COPY . /app

# Core engine has zero mandatory deps; install optional extras (yaml for config)
RUN pip install --no-cache-dir pyyaml || true

ENTRYPOINT ["python", "sast_agent.py"]
CMD ["scan", "--help"]
