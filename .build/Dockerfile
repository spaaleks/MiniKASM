FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install Caddy and ca-certificates
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
  && curl -fsSL "https://caddyserver.com/api/download?os=linux&arch=amd64" -o /usr/local/bin/caddy \
  && chmod +x /usr/local/bin/caddy \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN python -m pip install --upgrade pip \
 && python -m pip install -r requirements.txt

COPY src /app/src
COPY templates /app/templates
COPY static /app/static
COPY .build/caddy.json /app/caddy.json
COPY .build/start.sh /app/start.sh
RUN chmod +x /app/start.sh

EXPOSE 32090

ENV CONFIG_PATH=/config/users.yaml \
    PORT=32090 \
    FLASK_PORT=8080

CMD ["/app/start.sh"]
