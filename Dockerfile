FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md /app/
COPY router_dyndns /app/router_dyndns
RUN pip install --no-cache-dir .
RUN adduser --system --group --home /app routerpulse \
    && mkdir -p /data \
    && chown -R routerpulse:routerpulse /app /data
USER routerpulse

EXPOSE 8080
CMD ["router-dyndns", "serve", "--host", "0.0.0.0", "--port", "8080"]
