FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends nmap && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml ./
COPY osint ./osint
RUN pip install --no-cache-dir .
ENTRYPOINT ["osint"]
CMD ["--help"]
