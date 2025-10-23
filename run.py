from app import create_app
from app.k8s_client import init_k8s_client

app = create_app()

if __name__ == '__main__':
    with app.app_context():
        init_k8s_client()

    app.run(debug=True, host='0.0.0.0', port=8080)