"""Gunicorn entry point for the Log Parser container.

Runs the best-effort stale temp-dir sweep once at startup (the same cleanup
that ``python app.py`` does), then exposes the Flask app for the WSGI server.
"""

from app import app, _sweep_stale_dirs

_sweep_stale_dirs()

__all__ = ["app"]
