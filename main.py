import sys
import argparse
from flask import Flask
from flask_jwt_extended import JWTManager
from api.routes import api_blueprint
from db.db_sqlite import SQLiteDatabase

# Προσπάθεια import του cli.runner
try:
    from cli.runner import run_cli_command
except ImportError:
    run_cli_command = None

class CustomFlask(Flask):
    db = None

def create_app(config: dict = None, db_type: str = None) -> CustomFlask:
    app = CustomFlask(__name__)
    
    app.config.update(
        DATABASE_TYPE=db_type or "sqlite",
        DATABASE_URI=":memory:",
        JWT_SECRET_KEY="super-secret-key"
    )
    if config:
        app.config.update(config)
    
    app.db = SQLiteDatabase(app.config.get("DATABASE_URI"))
    app.db.connect()
    app.db.create_tables()

    app.register_blueprint(api_blueprint, url_prefix="/api")
    
    JWTManager(app)
    
    return app

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['server', 'cli'], default='server')
    parser.add_argument('--cli-command')
    args = parser.parse_args()

    app = create_app()

    if args.mode == 'server':
        app.run(debug=True, host='0.0.0.0', port=5000)
    elif args.mode == 'cli':
        if run_cli_command:
            run_cli_command(app, args.cli_command)
            sys.exit(0)
        else:
            print("CLI runner not available.")
            sys.exit(1)

if __name__ == "__main__":
    main()