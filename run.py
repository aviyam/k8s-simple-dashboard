from app import create_app
from app.k8s_client import init_k8s_client, K8sConnectionError

app = create_app()

if __name__ == '__main__':
    with app.app_context():
        try:
            init_k8s_client()
        except K8sConnectionError as e:
            print(f"Warning: {e}")
            print("Starting dashboard anyway - error page will be shown to users.")

    app.run(debug=True, host='0.0.0.0', port=8080)