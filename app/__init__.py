import os

from flask import Flask

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from flask_wtf.csrf import CSRFProtect

from dotenv import load_dotenv

from .db import init_db
from .routes import bp
from .auth import auth_bp


# =========================================================
# Load environment variables
# =========================================================

load_dotenv()


# =========================================================
# CSRF Protection
# =========================================================

csrf = CSRFProtect()


# =========================================================
# Application Factory
# =========================================================

def create_app():

    app = Flask(__name__)

    # -----------------------------------------------------
    # Secret Key
    # -----------------------------------------------------

    secret_key = os.environ.get("SECRET_KEY")

    if not secret_key:
        raise RuntimeError(
            "SECRET_KEY environment variable is required."
        )

    app.config["SECRET_KEY"] = secret_key

    # -----------------------------------------------------
    # Session Cookie Security
    # -----------------------------------------------------

    # Prevent JavaScript from accessing the session cookie.
    app.config["SESSION_COOKIE_HTTPONLY"] = True

    # Helps protect against cross-site request forgery.
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    # Local development uses HTTP, so this remains False.
    #
    # When deploying the application over HTTPS,
    # set SESSION_COOKIE_SECURE=true in .env.
    secure_cookie = os.environ.get(
        "SESSION_COOKIE_SECURE",
        "false"
    ).lower() == "true"

    app.config["SESSION_COOKIE_SECURE"] = secure_cookie

    # -----------------------------------------------------
    # Session Lifetime
    # -----------------------------------------------------

    app.config["PERMANENT_SESSION_LIFETIME"] = 3600

    # -----------------------------------------------------
    # CSRF Protection
    # -----------------------------------------------------

    csrf.init_app(app)

    # -----------------------------------------------------
    # Database
    # -----------------------------------------------------

    app.config["DATABASE"] = os.path.join(
        os.path.dirname(
            os.path.dirname(
                os.path.abspath(__file__)
            )
        ),
        "soc.db"
    )

    # -----------------------------------------------------
    # Rate Limiter
    # -----------------------------------------------------

    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=[
            "200 per day",
            "50 per hour"
        ]
    )

    # Store limiter so other parts of the application
    # can access it through app.extensions.
    app.extensions["limiter"] = limiter

    # -----------------------------------------------------
    # Register Authentication Routes
    # -----------------------------------------------------

    app.register_blueprint(auth_bp)

    # -----------------------------------------------------
    # Register Main Application Routes
    # -----------------------------------------------------

    app.register_blueprint(bp)

    # -----------------------------------------------------
    # Initialize Database
    # -----------------------------------------------------

    init_db(app)

    # -----------------------------------------------------
    # Return Application
    # -----------------------------------------------------

    return app
