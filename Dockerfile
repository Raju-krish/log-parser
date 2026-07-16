# Log Parser container image
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install runtime deps first (better layer caching). gunicorn is the
# production WSGI server used inside the container.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn==23.0.0

# Copy the application code
COPY . .

# Run as an unprivileged user
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /data/workspaces \
    && chown -R appuser:appuser /app /data
USER appuser

EXPOSE 5100

# Simple stdlib-based healthcheck (no curl in the slim image)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5100/').status==200 else 1)"

# IMPORTANT: exactly ONE worker. Uploaded-log state is held in memory per
# process, so multiple workers would each see only part of a user's session.
# Threads provide concurrency within the single worker.
# --limit-request-line: raise from gunicorn's 4094-byte default so large source
# selections (which encode picked/excluded ids in the query string) don't get
# rejected with a 400 that would silently freeze the AJAX log view.
CMD ["gunicorn", "--workers", "1", "--threads", "8", "--timeout", "120", \
     "--limit-request-line", "8190", \
     "--bind", "0.0.0.0:5100", "wsgi:app"]
