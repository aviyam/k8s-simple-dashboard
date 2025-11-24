from flask import Flask
from flask_sock import Sock

sock = Sock()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'a-super-secret-key-for-dev'
    sock.init_app(app)

    # Import views to register sock routes
    from . import views
    
    # Register blueprint
    app.register_blueprint(views.bp)

    @app.route('/health')
    def health_check():
        return "OK"

    return app