import sys
import os

# Ensure the root project directory is in sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

class VercelPathFixMiddleware:
    """Ensures paths passed through Vercel rewrites or direct invocations map correctly to Flask routes."""
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        if path.startswith("/api/index.py"):
            clean = path[len("/api/index.py"):]
            environ["PATH_INFO"] = clean if clean else "/"
        elif path.startswith("/api/index"):
            clean = path[len("/api/index"):]
            if clean and clean.startswith("/"):
                environ["PATH_INFO"] = clean
            elif not clean:
                environ["PATH_INFO"] = "/"
        return self.wsgi_app(environ, start_response)

try:
    from app import app
    app.wsgi_app = VercelPathFixMiddleware(app.wsgi_app)
    handler = app
except Exception as e:
    import traceback
    err_traceback = traceback.format_exc()
    from flask import Flask, jsonify

    app = Flask(__name__)

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def catch_all_error(path):
        return jsonify({
            "status": 500,
            "error": "Serverless Function Startup Exception",
            "message": str(e),
            "traceback": err_traceback.split("\n")
        }), 500

    handler = app
