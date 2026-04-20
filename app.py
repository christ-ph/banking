"""Point d'entrée de l'application bancaire Flask."""
from dotenv import load_dotenv
load_dotenv()   # Doit être AVANT tout import de config

from flask import Flask
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flasgger import Swagger
from config import Config
from models import db
from routes import api

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    Migrate(app, db)
    JWTManager(app)
    CORS(app)
    Swagger(app, template={
        "info": {"title": "Banking API", "version": "1.0"},
        "securityDefinitions": {
            "Bearer": {"type": "apiKey", "name": "Authorization", "in": "header"}
        }
    })

    app.register_blueprint(api, url_prefix='/api/v1')
    return app

# Création de l'instance pour Gunicorn (production)
app = create_app()

# Créer les tables si elles n'existent pas (idempotent)
with app.app_context():
    db.create_all()
    print("Tables vérifiées/créées (si absentes)")

if __name__ == '__main__':
    app.run(debug=True)