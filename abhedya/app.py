"""
app.py — Abhedya application factory
"""
import logging
from flask import Flask
from routes.crypto_routes import api
from routes.ui_routes import ui

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")

    # Security settings
    app.config.update(
        SECRET_KEY             = "change-this-in-production-use-env-var",
        MAX_CONTENT_LENGTH     = 110 * 1024 * 1024,   # 110 MB upload ceiling
        JSON_SORT_KEYS         = False,
        PROPAGATE_EXCEPTIONS   = False,
    )

    # Blueprints
    app.register_blueprint(ui)
    app.register_blueprint(api, url_prefix="/api")

    # Generic JSON error handlers
    @app.errorhandler(413)
    def too_large(e):
        from flask import jsonify
        return jsonify({"success": False, "error": "File exceeds the 100 MB size limit."}), 413

    @app.errorhandler(404)
    def not_found(e):
        from flask import jsonify
        return jsonify({"success": False, "error": "Endpoint not found."}), 404

    @app.errorhandler(500)
    def server_error(e):
        from flask import jsonify
        return jsonify({"success": False, "error": "Internal server error."}), 500

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=False, port=5000, host="127.0.0.1")
