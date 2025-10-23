from flask import Flask

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'a-super-secret-key-for-dev'

    from . import views
    app.register_blueprint(views.bp)

    @app.route('/health')
    def health_check():
        return "OK"

    return app