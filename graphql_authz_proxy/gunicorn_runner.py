from gunicorn.app.base import BaseApplication

class GunicornApp(BaseApplication):
    def __init__(self, app, options=None):
        self.application = app
        self.options = options or {}
        super().__init__()

    def load_config(self):
        for key, value in self.options.items():
            self.cfg.set(key, value)

    def load(self):
        return self.application


def run_with_gunicorn(app, host, port, workers=2):
    options = {
        "bind": f"{host}:{port}",
        "workers": workers,
    }

    GunicornApp(app, options).run()
