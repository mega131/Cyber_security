from flask import Flask
from app.config import Config
from app.models.evidence import init_db
from app.routes.dashboard import dashboard_bp
from app.routes.evidence import evidence_bp
from app.routes.integrity import integrity_bp
from app.routes.reports import reports_bp

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure required runtime folders exist
    Config.UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
    Config.DATA_FOLDER.mkdir(parents=True, exist_ok=True)

    # Initialize SQLite tables
    with app.app_context():
        init_db()

    # Register modular Blueprints
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(evidence_bp)
    app.register_blueprint(integrity_bp)
    app.register_blueprint(reports_bp)

    return app
