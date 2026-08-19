FROM python:3.12-slim

# Install sing-box binary (for check + staging validation)
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && \
    SBVER=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest \
      | grep '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/') && \
    curl -fsSL "https://github.com/SagerNet/sing-box/releases/latest/download/sing-box-${SBVER}-linux-amd64.tar.gz" \
    | tar -xz --strip-components=1 -C /usr/local/bin/ && \
    apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/proxy-dashboard

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN mkdir -p data app/static

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8787"]
