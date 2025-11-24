# K8s Simple Dashboard

A lightweight, Python-based Kubernetes dashboard built with Flask. This dashboard provides a simple and intuitive interface to view and manage your Kubernetes cluster resources.

## Features

*   **Cluster Overview**: View cluster status and node information.
*   **Workload Management**:
    *   **Pods**: List, filter by namespace/node, delete, restart, and view details.
    *   **Logs**: Real-time log streaming with ANSI color support.
    *   **Deployments, StatefulSets, DaemonSets, ReplicaSets, Jobs, CronJobs**: View lists and detailed descriptions.
*   **Configuration**:
    *   **ConfigMaps & Secrets**: View and inspect configuration resources.
    *   **Secret Decoding**: Securely decode and view secret values directly in the UI.
*   **Network**:
    *   **Services & Ingresses**: Monitor network resources.
*   **Storage**:
    *   **PersistentVolumes & PVCs**: View storage allocations.
*   **Images**: List all unique container images running in the cluster.

## Prerequisites

*   Python 3.9+
*   A running Kubernetes cluster
*   `kubectl` configured with access to the cluster (standard `~/.kube/config` or `KUBECONFIG` environment variable)
*   [uv](https://github.com/astral-sh/uv) (for dependency management)

## Getting Started

### Local Development

1.  **Clone the repository:**

    ```bash
    git clone <repository-url>
    cd k8s-simple-dashboard
    ```

2.  **Install dependencies:**

    This project uses `uv` for fast dependency management.

    ```bash
    uv sync
    ```

3.  **Run the application:**

    ```bash
    uv run run.py
    ```

    The dashboard will be available at `http://localhost:8080`.

### Running with Docker

1.  **Build the image:**

    ```bash
    docker build -t k8s-dashboard .
    ```

2.  **Run the container:**

    You need to mount your kubeconfig file so the container can access your cluster.

    ```bash
    docker run -p 8080:8080 \
      -v ~/.kube/config:/root/.kube/config \
      k8s-dashboard
    ```

### Running with Docker Compose

1.  **Start the service:**

    ```bash
    docker-compose up --build
    ```

    Ensure your `docker-compose.yaml` is configured to mount the kubeconfig correctly if running outside of a cluster that provides service account tokens.

## Configuration

The application relies on the standard Kubernetes client configuration. It will automatically attempt to load configuration from:

1.  In-cluster configuration (if running inside a pod).
2.  `KUBECONFIG` environment variable.
3.  `~/.kube/config` file.

## Tech Stack

*   **Backend**: Python, Flask, Gunicorn
*   **Frontend**: HTML, CSS (Vanilla), JavaScript
*   **Kubernetes**: Official Python Client
*   **Package Manager**: uv
