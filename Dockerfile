FROM python:3.12-slim

WORKDIR /app
COPY . /app

# Core engine has zero mandatory deps; openai is optional (AI layer)
RUN pip install --no-cache-dir -r requirements.txt || true

ENTRYPOINT ["python", "sast_agent.py"]
CMD ["scan", "--help"]
