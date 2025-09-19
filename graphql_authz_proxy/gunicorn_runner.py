"""Run the FastAPI app with Gunicorn for production deployments."""
from typing import override

from flask import Flask
from gunicorn.app.base import BaseApplication


class GunicornApp(BaseApplication):

    """Custom Gunicorn application to run a Flask app with specified options."""

    @override
    def __init__(self, app: Flask, options: dict | None = None) -> None:
        self.application = app
        self.options = options or {}
        super().__init__()

    @override
    def load_config(self) -> None:
        for key, value in self.options.items():
            self.cfg.set(key, value)

    @override
    def load(self) -> "GunicornApp":
        return self.application


def run_with_gunicorn(app: Flask, host: str, port: int, workers: int = 2) -> None:
    """Run the Flask app with Gunicorn."""
    options = {
        "bind": f"{host}:{port}",
        "workers": workers,
    }

    GunicornApp(app, options).run()
