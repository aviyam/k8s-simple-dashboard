from flask import Blueprint, render_template, request, redirect, url_for, flash, Response
from . import k8s_client
from datetime import datetime, timedelta
import yaml

bp = Blueprint('main', __name__)

@bp.context_processor
def inject_namespaces():
    """
    Injects the list of all namespaces into the template context.
    Fails gracefully if the cluster is unavailable.
    """
    try:
        namespaces = k8s_client.get_namespaces()
        return dict(all_namespaces=namespaces)
    except k8s_client.K8sConnectionError:
        return dict(all_namespaces=[])

@bp.context_processor
def inject_nodes():
    """
    Injects the list of node names into all templates.
    Fails gracefully if the cluster is unavailable.
    """
    try:
        nodes = k8s_client.get_nodes()
        node_names = sorted([node['name'] for node in nodes])
        return dict(all_nodes=node_names)
    except k8s_client.K8sConnectionError:
        return dict(all_nodes=[])



@bp.errorhandler(k8s_client.K8sConnectionError)
def handle_k8s_connection_error(error):
    """Renders a custom error page for K8s connection issues."""
    return render_template('error_k8s_connection.html', error_message=str(error)), 500

@bp.route('/')
def index():
    """Renders the main cluster status page."""
    cluster_status = k8s_client.get_cluster_status()
    nodes = k8s_client.get_nodes()
    return render_template('status.html', status=cluster_status, nodes=nodes)

@bp.route('/pods')
def pods_list():
    """Displays a list of all pods."""
    namespace = request.args.get('namespace', 'all')
    node_filter = request.args.get('node', None)
    pods = k8s_client.get_pods(namespace=namespace, node_name=node_filter)
    return render_template('pods.html', pods=pods, namespace=namespace, node_filter=node_filter)


@bp.route('/pods/delete/<namespace>/<name>', methods=['POST'])
def delete_pod(namespace, name):
    """Handles the deletion of a pod."""
    k8s_client.delete_pod(name, namespace)
    # Redirect back to the pods list
    flash(f"Pod '{name}' has been scheduled for deletion.", "success")
    return redirect(url_for('main.pods_list', namespace=namespace))

# In K8s, a 'restart' is typically done by deleting the pod and letting
# the controller (like a Deployment) recreate it.
@bp.route('/pods/restart/<namespace>/<name>', methods=['POST'])
def restart_pod(namespace, name):
    """Handles the 'restart' of a pod by deleting it."""
    k8s_client.delete_pod(name, namespace)
    flash(f"Pod '{name}' has been scheduled for restart.", "success")
    return redirect(url_for('main.pods_list', namespace=namespace))


@bp.route('/pods/describe/<namespace>/<name>')
def describe_pod(namespace, name):
    """Shows the detailed YAML description of a pod."""
    details = k8s_client.get_pod_details(name, namespace)
    return render_template('pod_details.html', name=name, details=details)

@bp.route('/deployments')
def deployments_list():
    """Displays a list of all deployments."""
    namespace = request.args.get('namespace', 'all')
    deployments = k8s_client.get_deployments(namespace)
    return render_template('deployments.html', deployments=deployments, namespace=namespace)

@bp.route('/images')
def images_list():
    """Displays a list of unique container images used in the cluster."""
    images = k8s_client.get_used_images()
    return render_template('images.html', images=images)

@bp.route('/pods/logs/<namespace>/<name>')
def show_logs_page(namespace, name):
    """Renders the HTML page for viewing pod logs."""
    return render_template('pod_logs.html', namespace=namespace, name=name)

@bp.route('/pods/logs/stream/<namespace>/<name>')
def stream_logs(namespace, name):
    """Provides a real-time stream of pod logs."""
    log_generator = k8s_client.stream_pod_logs(name, namespace)
    # The official mimetype for Server-Sent Events is 'text/event-stream'
    return Response(log_generator, mimetype='text/event-stream')


@bp.route('/deployments/describe/<namespace>/<name>')
def describe_deployment(namespace, name):
    """Renders the stylized description page for a deployment."""
    details = k8s_client.get_deployment_details(name, namespace)
    return render_template('deployment_details.html', details=details)



@bp.route('/configmaps')
def config_maps_list():
    namespace = request.args.get('namespace', 'all')
    items = k8s_client.get_config_maps(namespace)
    return render_template('configmaps.html', items=items, namespace=namespace)

@bp.route('/configmaps/describe/<namespace>/<name>')
def describe_config_map(namespace, name):
    details_dict = k8s_client.get_config_map_details(name, namespace)
    details_yaml = yaml.dump(details_dict)
    return render_template('resource_details.html', kind='ConfigMap', name=name, namespace=namespace, details_yaml=details_yaml, back_link='main.config_maps_list')

@bp.route('/services')
def services_list():
    namespace = request.args.get('namespace', 'all')
    items = k8s_client.get_services(namespace)
    return render_template('services.html', items=items, namespace=namespace)

@bp.route('/services/describe/<namespace>/<name>')
def describe_service(namespace, name):
    details_dict = k8s_client.get_service_details(name, namespace)
    details_yaml = yaml.dump(details_dict)
    return render_template('resource_details.html', kind='Service', name=name, namespace=namespace, details_yaml=details_yaml, back_link='main.services_list')

@bp.route('/persistent-volumes')
def persistent_volumes_list():
    items = k8s_client.get_persistent_volumes()
    return render_template('persistent_volumes.html', items=items)

@bp.route('/persistent-volumes/describe/<name>')
def describe_persistent_volume(name):
    details_dict = k8s_client.get_persistent_volume_details(name)
    details_yaml = yaml.dump(details_dict)
    return render_template('resource_details.html', kind='PersistentVolume', name=name, namespace=None, details_yaml=details_yaml, back_link='main.persistent_volumes_list')

@bp.route('/secrets')
def secrets_list():
    namespace = request.args.get('namespace', 'all')
    items = k8s_client.get_secrets(namespace)
    return render_template('secrets.html', items=items, namespace=namespace)


# Add base64 and jsonify to the import line at the top
from flask import Blueprint, render_template, request, redirect, url_for, flash, Response, jsonify
import base64


@bp.route('/secrets/describe/<namespace>/<name>')
def describe_secret(namespace, name):
    details = k8s_client.get_secret_details(name, namespace)
    return render_template('secret_details.html', details=details)


@bp.route('/secrets/decode/<namespace>/<name>', methods=['POST'])
def decode_secret_data(namespace, name):
    """Handles the decoding request by calling the k8s_client."""
    try:
        key_to_decode = request.form['key']
        # Call the new, robust function from our client
        decoded_value = k8s_client.decode_secret_key(name, namespace, key_to_decode)
        return jsonify({'decoded_value': decoded_value})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/persistent-volume-claims')
def pvcs_list():
    namespace = request.args.get('namespace', 'all')
    items = k8s_client.get_pvcs(namespace)
    return render_template('pvcs.html', items=items, namespace=namespace)

@bp.route('/persistent-volume-claims/describe/<namespace>/<name>')
def describe_pvc(namespace, name):
    details_dict = k8s_client.get_pvc_details(name, namespace)
    details_yaml = yaml.dump(details_dict)
    return render_template('resource_details.html', kind='PersistentVolumeClaim', name=name, namespace=namespace, details_yaml=details_yaml, back_link='main.pvcs_list')

@bp.route('/stateful-sets')
def stateful_sets_list():
    namespace = request.args.get('namespace', 'all')
    items = k8s_client.get_stateful_sets(namespace)
    return render_template('statefulsets.html', items=items, namespace=namespace)

@bp.route('/stateful-sets/describe/<namespace>/<name>')
def describe_stateful_set(namespace, name):
    details = k8s_client.get_stateful_set_details(name, namespace)
    return render_template('statefulset_details.html', details=details)


@bp.route('/daemon-sets')
def daemon_sets_list():
    namespace = request.args.get('namespace', 'all')
    items = k8s_client.get_daemon_sets(namespace)
    return render_template('daemonsets.html', items=items, namespace=namespace)

@bp.route('/daemon-sets/describe/<namespace>/<name>')
def describe_daemon_set(namespace, name):
    details = k8s_client.get_daemon_set_details(name, namespace)
    return render_template('daemonset_details.html', details=details)

@bp.route('/replica-sets')
def replica_sets_list():
    namespace = request.args.get('namespace', 'all')
    items = k8s_client.get_replica_sets(namespace)
    return render_template('replicasets.html', items=items, namespace=namespace)

@bp.route('/replica-sets/describe/<namespace>/<name>')
def describe_replica_set(namespace, name):
    details = k8s_client.get_replica_set_details(name, namespace)
    return render_template('replicaset_details.html', details=details)


@bp.route('/jobs')
def jobs_list():
    namespace = request.args.get('namespace', 'all')
    items = k8s_client.get_jobs(namespace)
    return render_template('jobs.html', items=items, namespace=namespace)

@bp.route('/jobs/describe/<namespace>/<name>')
def describe_job(namespace, name):
    details = k8s_client.get_job_details(name, namespace)
    return render_template('job_details.html', details=details)


@bp.route('/cron-jobs')
def cron_jobs_list():
    namespace = request.args.get('namespace', 'all')
    items = k8s_client.get_cron_jobs(namespace)
    return render_template('cronjobs.html', items=items, namespace=namespace)

@bp.route('/cron-jobs/describe/<namespace>/<name>')
def describe_cron_job(namespace, name):
    details_yaml = yaml.dump(k8s_client.get_cron_job_details(name, namespace))
    return render_template('resource_details.html', kind='CronJob', name=name, namespace=namespace, details_yaml=details_yaml, back_link='main.cron_jobs_list')

@bp.route('/ingresses')
def ingresses_list():
    namespace = request.args.get('namespace', 'all')
    items = k8s_client.get_ingresses(namespace)
    return render_template('ingresses.html', items=items, namespace=namespace)

@bp.route('/ingresses/describe/<namespace>/<name>')
def describe_ingress(namespace, name):
    details_yaml = yaml.dump(k8s_client.get_ingress_details(name, namespace))
    return render_template('resource_details.html', kind='Ingress', name=name, namespace=namespace, details_yaml=details_yaml, back_link='main.ingresses_list')

@bp.route('/nodes/describe/<name>')
def describe_node(name):
    """Renders the stylized description page for a node."""
    details = k8s_client.get_node_details(name)
    return render_template('node_details.html', details=details)