from flask import Flask

# Database connection to be insterted here

def create_app():
    app = Flask(__name__, static_url_path=f"/static")
    with app.app_context():
        from app import app
        app.register_blueprint(app)

        return app