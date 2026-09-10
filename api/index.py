import sys
import os

# Ensure the root project directory is in sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

try:
    from app import app
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
