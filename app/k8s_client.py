import os
import yaml
from datetime import datetime, timezone
from kubernetes import client, config, watch
from kubernetes.stream import stream as k8s_stream
import base64
from kubernetes.config.config_exception import ConfigException
from kubernetes.client.exceptions import ApiException


# Global API client instances
core_v1 = None
apps_v1 = None
batch_v1 = None
networking_v1 = None
custom_objects_api = None
current_context = None

class K8sConnectionError(Exception):
    """Custom exception for Kubernetes connection errors."""
    pass

def init_k8s_client(context_name=None):
    """Initializes all necessary Kubernetes API clients."""
    global core_v1, apps_v1, batch_v1, networking_v1, custom_objects_api, current_context
    try:
        try:
            config.load_incluster_config()
            current_context = "in-cluster"
        except ConfigException:
            config.load_kube_config(context=context_name)
            _, active_context = config.list_kube_config_contexts()
            if context_name:
                current_context = context_name
            elif active_context:
                current_context = active_context['name']
            else:
                current_context = "unknown"
    except (ConfigException, ApiException) as e:
        # Catch any configuration or API connection error and raise our custom exception
        raise K8sConnectionError(f"Could not connect to the Kubernetes cluster. Please check your kubeconfig file or cluster status. Details: {e}") from e

    core_v1 = client.CoreV1Api()
    apps_v1 = client.AppsV1Api()
    batch_v1 = client.BatchV1Api()
    networking_v1 = client.NetworkingV1Api()
    custom_objects_api = client.CustomObjectsApi()
    print(f"Kubernetes clients initialized successfully (Context: {current_context}).")


def get_contexts():
    """Returns a list of available contexts and the current context."""
    try:
        contexts, active_context = config.list_kube_config_contexts()
        if not contexts:
            return [], None
        return [c['name'] for c in contexts], current_context
    except ConfigException:
        return [], None


def _format_age(creation_timestamp):
    """Formats a timedelta into a human-readable age string."""
    if not creation_timestamp:
        return "N/A"
    now = datetime.now(timezone.utc)
    delta = now - creation_timestamp
    if delta.days > 0:
        return f"{delta.days}d"
    elif delta.seconds >= 3600:
        return f"{delta.seconds // 3600}h"
    elif delta.seconds >= 60:
        return f"{delta.seconds // 60}m"
    else:
        return f"{delta.seconds}s"


def decode_secret_key(name, namespace, key):
    """Fetches a single secret and decodes a specific key."""
    if not core_v1:
        init_k8s_client()

    secret = core_v1.read_namespaced_secret(name=name, namespace=namespace)
    encoded_value = secret.data.get(key)

    if encoded_value:
        return base64.b64decode(encoded_value).decode('utf-8')
    else:
        raise KeyError(f"Key '{key}' not found in secret '{name}'")

def _get_dir_size(path):
    """Calculates the total size of a directory in bytes."""
    total_size = 0
    try:
        for dirpath, dirnames, filenames in os.walk(path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                # Skip if it's a symlink or not a file
                if not os.path.islink(fp):
                    total_size += os.path.getsize(fp)
    except FileNotFoundError:
        return 0 # Return 0 if path doesn't exist
    return total_size

def _format_bytes(size_bytes):
    """Converts bytes into a human-readable string (KB, MB, GB)."""
    if size_bytes == 0:
        return "0 B"
    power = 1024
    n = 0
    power_labels = {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size_bytes >= power and n < len(power_labels):
        size_bytes /= power
        n += 1
    return f"{size_bytes:.1f} {power_labels[n]}B"


# --- CORE V1 RESOURCES ---
# --- CORE V1 RESOURCES ---

# ... (other code) ...

def get_cluster_status():
    """
    Aggregates overall cluster status, including detailed disk usage
    for paths defined in config.yaml.
    """
    # ... (pod_counts and component_statuses logic is unchanged) ...
    if not core_v1: init_k8s_client()
    pod_list = core_v1.list_pod_for_all_namespaces()
    pod_counts = {'Running': 0, 'Pending': 0, 'Succeeded': 0, 'Failed': 0, 'Unknown': 0}
    for pod in pod_list.items:
        if pod.status.phase in pod_counts: pod_counts[pod.status.phase] += 1
    component_statuses = []
    try:
        status_list = core_v1.list_component_status()
        for component in status_list.items:
            healthy_condition = next((c for c in component.conditions if c.type == "Healthy"), None)
            is_healthy = healthy_condition.status == "True" if healthy_condition else False
            component_statuses.append({'name': component.metadata.name, 'healthy': is_healthy})
    except Exception as e:
        print(f"Could not retrieve component statuses: {e}")
        component_statuses.append({'name': 'component-status-api', 'healthy': False,
                                   'message': 'API not available or insufficient permissions.'})
    return {
        'pod_counts': pod_counts,
        'component_statuses': component_statuses
    }


def get_pods(namespace="all", node_name=None):
    if not core_v1: init_k8s_client()
    # ... (rest of function is unchanged)
    if namespace == "all":
        pod_list_items = core_v1.list_pod_for_all_namespaces().items
    else:
        pod_list_items = core_v1.list_namespaced_pod(namespace).items
    pods = []
    for item in pod_list_items:
        if node_name and node_name != 'all' and item.spec.node_name != node_name:
            continue
        restarts = 0
        if item.status.container_statuses:
            for container in item.status.container_statuses:
                restarts += container.restart_count
        pod_info = {'name': item.metadata.name, 'namespace': item.metadata.namespace, 'status': item.status.phase,
                    'ip': item.status.pod_ip, 'node': item.spec.node_name, 'restarts': restarts}
        pods.append(pod_info)
    return pods


def get_pod_details(name, namespace="default"):
    if not core_v1: init_k8s_client()
    # ... (rest of function is unchanged)
    pod_data = core_v1.read_namespaced_pod(name=name, namespace=namespace)
    try:
        field_selector = f"involvedObject.name={name},involvedObject.namespace={namespace}"
        event_list = core_v1.list_namespaced_event(namespace=namespace, field_selector=field_selector)
        events = [
            {'last_seen': item.last_timestamp.strftime("%Y-%m-%d %H:%M:%S"), 'type': item.type, 'reason': item.reason,
             'message': item.message} for item in event_list.items]
    except client.ApiException as e:
        print(f"Could not fetch events for pod {name}: {e}")
        events = []
    details = {'name': pod_data.metadata.name, 'namespace': pod_data.metadata.namespace,
               'node': pod_data.spec.node_name, 'status': pod_data.status.phase, 'pod_ip': pod_data.status.pod_ip,
               'start_time': pod_data.status.start_time.strftime(
                   "%Y-%m-%d %H:%M:%S") if pod_data.status.start_time else 'N/A', 'labels': pod_data.metadata.labels,
               'annotations': pod_data.metadata.annotations, 'service_account': pod_data.spec.service_account_name,
               'containers': [], 'volumes': [], 'conditions': [],
               'events': sorted(events, key=lambda x: x['last_seen'], reverse=True)}
    if pod_data.status.container_statuses:
        for c_status in pod_data.status.container_statuses:
            c_spec = next((c for c in pod_data.spec.containers if c.name == c_status.name), None)
            details['containers'].append({'name': c_status.name, 'image': c_status.image, 'ready': c_status.ready,
                                          'restarts': c_status.restart_count,
                                          'state': list(c_status.state.to_dict().keys())[0],
                                          'ports': [p.to_dict() for p in
                                                    c_spec.ports] if c_spec and c_spec.ports else [],
                                          'env': [e.to_dict() for e in c_spec.env] if c_spec and c_spec.env else [],
                                          'mounts': [m.to_dict() for m in
                                                     c_spec.volume_mounts] if c_spec and c_spec.volume_mounts else []})
    if pod_data.spec.volumes:
        for v in pod_data.spec.volumes:
            volume_source = v.to_dict()
            source_type = [k for k in volume_source if k != 'name'][0]
            source_details = volume_source.get(source_type)
            details['volumes'].append({'name': v.name, 'type': source_type, 'details': source_details})
    if pod_data.status.conditions:
        for cond in pod_data.status.conditions:
            details['conditions'].append({'type': cond.type, 'status': cond.status,
                                          'last_transition_time': cond.last_transition_time.strftime(
                                              "%Y-%m-%d %H:%M:%S") if cond.last_transition_time else 'N/A'})
    return details


def delete_pod(name, namespace):
    """Deletes a pod."""
    if not core_v1: init_k8s_client()
    try:
        core_v1.delete_namespaced_pod(name=name, namespace=namespace)
        print(f"Pod {name} in namespace {namespace} deleted.")
    except client.ApiException as e:
        print(f"Error deleting pod {name}: {e}")
        raise


def stream_pod_logs(name, namespace="default"):
    if not core_v1: init_k8s_client()
    # ... (rest of function is unchanged)
    try:
        stream = core_v1.read_namespaced_pod_log(name=name, namespace=namespace, follow=True, _preload_content=False)
        for line in stream:
            decoded_line = line.decode('utf-8')
            yield decoded_line
    except Exception as e:
        error_message = f"--- LOG STREAM ERROR: {e} ---"
        yield error_message


def stream_cluster_events():
    """
    Generates a stream of real-time cluster events.
    """
    if not core_v1:
        init_k8s_client()
    
    w = watch.Watch()
    try:
        # Watch for events in all namespaces
        # We use a timeout to allow the generator to check for client disconnection or other issues periodically
        for event in w.stream(core_v1.list_event_for_all_namespaces, timeout_seconds=60):
            event_obj = event['object']
            # We are primarily interested in new events being added to the history
            if event['type'] == 'ADDED':
                yield event_obj
    except Exception as e:
        print(f"Event stream error: {e}")


def terminal_stream(name, namespace, container, shell=None):
    """
    Establishes a websocket-like stream to a pod container.
    Tries multiple shells in order: /bin/sh, /bin/ash, /bin/bash
    """
    if not core_v1:
        init_k8s_client()
    
    # List of shells to try in order
    shells_to_try = [shell] if shell else ['/bin/sh', '/bin/ash', '/bin/bash']
    
    last_error = None
    for shell_cmd in shells_to_try:
        if shell_cmd is None:
            continue
        try:
            stream = k8s_stream(
                core_v1.connect_get_namespaced_pod_exec,
                name,
                namespace,
                container=container,
                command=[shell_cmd],
                stderr=True, stdin=True,
                stdout=True, tty=True,
                _preload_content=False
            )
            return stream
        except Exception as e:
            last_error = e
            continue
    
    # If all shells failed, raise the last error
    raise Exception(f"Could not connect to container with any shell. Last error: {last_error}")


def get_nodes():
    if not core_v1: init_k8s_client()

    pod_list = core_v1.list_pod_for_all_namespaces()
    pod_counts = {}
    for pod in pod_list.items:
        node_name = pod.spec.node_name
        if node_name:
            pod_counts[node_name] = pod_counts.get(node_name, 0) + 1
    node_list = core_v1.list_node()
    nodes = []
    for node in node_list.items:
        status = "Unknown"
        if node.status.conditions:
            ready_condition = next((c for c in node.status.conditions if c.type == "Ready"), None)
            if ready_condition:
                status = "Ready" if ready_condition.status == "True" else "NotReady"
        roles = [key.split('/')[-1] for key in node.metadata.labels if "node-role.kubernetes.io" in key]
        role_str = ",".join(roles) if roles else "<none>"
        taints = []
        if node.spec.taints:
            for taint in node.spec.taints:
                taints.append(f"{taint.key}={taint.value or ''}:{taint.effect}")
        taint_str = ",".join(taints) if taints else "<none>"
        node_info = {'name': node.metadata.name, 'status': status, 'role': role_str, 'taints': taint_str,
                     'version': node.status.node_info.kubelet_version,
                     'age': _format_age(node.metadata.creation_timestamp),
                     'pods': pod_counts.get(node.metadata.name, 0)}
        nodes.append(node_info)
    return nodes


def get_node_details(name):
    """
    Gets detailed, formatted information for a specific node,
    including its pods and events.
    """
    if not core_v1:
        init_k8s_client()

    # Get the main node object
    node_data = core_v1.read_node(name=name)

    # Get events for this Node
    events = []
    try:
        field_selector = f"involvedObject.uid={node_data.metadata.uid}"
        event_list = core_v1.list_event_for_all_namespaces(field_selector=field_selector)
        events = [{'last_seen': item.last_timestamp.strftime("%Y-%m-%d %H:%M:%S") if item.last_timestamp else 'N/A',
                   'type': item.type, 'reason': item.reason, 'message': item.message} for item in event_list.items]
    except client.ApiException as e:
        print(f"Could not fetch events for Node {name}: {e}")

    # Get pods on this node (we can reuse the get_pods function)
    pods_on_node = get_pods(node_name=name)

    details = {
        'name': node_data.metadata.name,
        'creation_timestamp': node_data.metadata.creation_timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        'labels': node_data.metadata.labels,
        'annotations': node_data.metadata.annotations,
        'taints': [f"{t.key}={t.value or ''}:{t.effect}" for t in
                   node_data.spec.taints] if node_data.spec.taints else [],
        'system_info': node_data.status.node_info.to_dict(),
        'conditions': [{'type': c.type, 'status': c.status, 'message': c.message} for c in node_data.status.conditions],
        'capacity': node_data.status.capacity,
        'allocatable': node_data.status.allocatable,
        'pods': pods_on_node,
        'events': sorted(events, key=lambda x: x['last_seen'], reverse=True)
    }
    return details

def get_config_maps(namespace="all"):
    if not core_v1: init_k8s_client()
    # ... (rest of function is unchanged)
    if namespace == "all":
        items = core_v1.list_config_map_for_all_namespaces().items
    else:
        items = core_v1.list_namespaced_config_map(namespace).items
    return [
        {'name': item.metadata.name, 'namespace': item.metadata.namespace, 'keys': len(item.data) if item.data else 0,
         'age': _format_age(item.metadata.creation_timestamp)} for item in items]


def get_config_map_details(name, namespace):
    if not core_v1: init_k8s_client()
    return core_v1.read_namespaced_config_map(name=name, namespace=namespace).to_dict()


def get_services(namespace="all"):
    if not core_v1: init_k8s_client()
    # ... (rest of function is unchanged)
    if namespace == "all":
        items = core_v1.list_service_for_all_namespaces().items
    else:
        items = core_v1.list_namespaced_service(namespace).items
    return [{'name': item.metadata.name, 'namespace': item.metadata.namespace, 'type': item.spec.type,
             'cluster_ip': item.spec.cluster_ip,
             'ports': ", ".join([str(p.port) for p in item.spec.ports]) if item.spec.ports else '',
             'age': _format_age(item.metadata.creation_timestamp)} for item in items]


def get_service_details(name, namespace):
    if not core_v1: init_k8s_client()
    return core_v1.read_namespaced_service(name=name, namespace=namespace).to_dict()


def get_persistent_volumes():
    if not core_v1: init_k8s_client()
    # ... (rest of function is unchanged)
    items = core_v1.list_persistent_volume().items
    return [{'name': item.metadata.name, 'capacity': item.spec.capacity.get('storage', 'N/A'),
             'access_modes': ", ".join(item.spec.access_modes), 'status': item.status.phase,
             'claim': f"{item.spec.claim_ref.namespace}/{item.spec.claim_ref.name}" if item.spec.claim_ref else '',
             'age': _format_age(item.metadata.creation_timestamp)} for item in items]


def get_persistent_volume_details(name):
    if not core_v1: init_k8s_client()
    return core_v1.read_persistent_volume(name=name).to_dict()


def get_secrets(namespace="all"):
    if not core_v1: init_k8s_client()
    # ... (rest of function is unchanged)
    if namespace == "all":
        items = core_v1.list_secret_for_all_namespaces().items
    else:
        items = core_v1.list_namespaced_secret(namespace).items
    return [{'name': item.metadata.name, 'namespace': item.metadata.namespace, 'type': item.type,
             'data_keys': len(item.data) if item.data else 0, 'age': _format_age(item.metadata.creation_timestamp)} for
            item in items]


def get_secret_details(name, namespace):
    """
    Gets detailed, formatted information for a specific Secret.
    """
    if not core_v1:
        init_k8s_client()

    secret_data = core_v1.read_namespaced_secret(name=name, namespace=namespace)

    events = []
    try:
        field_selector = f"involvedObject.uid={secret_data.metadata.uid}"
        event_list = core_v1.list_namespaced_event(namespace=namespace, field_selector=field_selector)
        events = [{'last_seen': item.last_timestamp.strftime("%Y-%m-%d %H:%M:%S") if item.last_timestamp else 'N/A',
                   'type': item.type, 'reason': item.reason, 'message': item.message} for item in event_list.items]
    except client.ApiException as e:
        print(f"Could not fetch events for Secret {name}: {e}")

    details = {
        'name': secret_data.metadata.name,
        'namespace': secret_data.metadata.namespace,
        'creation_timestamp': secret_data.metadata.creation_timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        'labels': secret_data.metadata.labels,
        'annotations': secret_data.metadata.annotations,
        'type': secret_data.type,
        'data': secret_data.data or {},  # Pass the raw, encoded data
        'events': sorted(events, key=lambda x: x['last_seen'], reverse=True)
    }
    return details


def get_pvcs(namespace="all"):
    if not core_v1: init_k8s_client()
    # ... (rest of function is unchanged)
    if namespace == "all":
        items = core_v1.list_persistent_volume_claim_for_all_namespaces().items
    else:
        items = core_v1.list_namespaced_persistent_volume_claim(namespace).items
    return [{'name': item.metadata.name, 'namespace': item.metadata.namespace, 'status': item.status.phase,
             'volume': item.spec.volume_name or '',
             'capacity': item.status.capacity.get('storage', 'N/A') if item.status.capacity else 'N/A',
             'access_modes': ", ".join(item.spec.access_modes) if item.spec.access_modes else '',
             'age': _format_age(item.metadata.creation_timestamp)} for item in items]


def get_pvc_details(name, namespace):
    if not core_v1: init_k8s_client()
    return core_v1.read_namespaced_persistent_volume_claim(name=name, namespace=namespace).to_dict()


# --- APPS V1 RESOURCES ---

def get_namespaces():
    """Fetches all namespaces in the cluster."""
    # ADD THIS CHECK
    if not core_v1:
        init_k8s_client()

    # Fetch the namespace list and extract just the names
    return sorted([ns.metadata.name for ns in core_v1.list_namespace().items])

def get_deployments(namespace="all"):
    if not apps_v1: init_k8s_client()
    # ... (rest of function is unchanged)
    if namespace == "all":
        deployment_list = apps_v1.list_deployment_for_all_namespaces()
    else:
        deployment_list = apps_v1.list_namespaced_deployment(namespace)
    deployments = []
    for item in deployment_list.items:
        deployment_info = {'name': item.metadata.name, 'namespace': item.metadata.namespace,
                           'replicas': item.spec.replicas, 'ready_replicas': item.status.ready_replicas or 0,
                           'available_replicas': item.status.available_replicas or 0,
                           'up_to_date_replicas': item.status.updated_replicas or 0,
                           'age': _format_age(item.metadata.creation_timestamp)}
        deployments.append(deployment_info)
    return deployments


def get_deployment_details(name, namespace="default"):
    if not apps_v1: init_k8s_client()
    # ... (rest of function is unchanged)
    deployment_data = apps_v1.read_namespaced_deployment(name=name, namespace=namespace)
    events = []
    try:
        field_selector = f"involvedObject.uid={deployment_data.metadata.uid}"
        event_list = core_v1.list_namespaced_event(namespace=namespace, field_selector=field_selector)
        events = [{'last_seen': item.last_timestamp.strftime("%Y-%m-%d %H:%M:%S") if item.last_timestamp else 'N/A',
                   'type': item.type, 'reason': item.reason, 'message': item.message} for item in event_list.items]
    except client.ApiException as e:
        print(f"Could not fetch events for deployment {name}: {e}")
    replica_sets = []
    try:
        rs_list = apps_v1.list_namespaced_replica_set(namespace=namespace, label_selector=client.V1LabelSelector(
            match_labels=deployment_data.spec.selector.match_labels).to_str())
        for rs in rs_list.items:
            if rs.metadata.owner_references and rs.metadata.owner_references[0].uid == deployment_data.metadata.uid:
                replica_sets.append({'name': rs.metadata.name, 'replicas': rs.status.replicas or 0,
                                     'ready_replicas': rs.status.ready_replicas or 0})
    except client.ApiException as e:
        print(f"Could not fetch ReplicaSets for deployment {name}: {e}")
    details = {'name': deployment_data.metadata.name, 'namespace': deployment_data.metadata.namespace,
               'creation_timestamp': deployment_data.metadata.creation_timestamp.strftime("%Y-%m-%d %H:%M:%S"),
               'labels': deployment_data.metadata.labels, 'annotations': deployment_data.metadata.annotations,
               'replicas_status': {'desired': deployment_data.spec.replicas,
                                   'total': deployment_data.status.replicas or 0,
                                   'available': deployment_data.status.available_replicas or 0,
                                   'unavailable': deployment_data.status.unavailable_replicas or 0,
                                   'updated': deployment_data.status.updated_replicas or 0, },
               'strategy': deployment_data.spec.strategy.type,
               'conditions': [{'type': c.type, 'status': c.status, 'reason': c.reason, 'message': c.message} for c in
                              deployment_data.status.conditions] if deployment_data.status.conditions else [],
               'pod_template': {'labels': deployment_data.spec.template.metadata.labels, 'containers': [
                   {'name': c.name, 'image': c.image, 'ports': [p.to_dict() for p in c.ports] if c.ports else [],
                    'env': [e.to_dict() for e in c.env] if c.env else []} for c in
                   deployment_data.spec.template.spec.containers],
                                'volumes': [{'name': v.name, 'type': list(v.to_dict().keys())[1]} for v in
                                            deployment_data.spec.template.spec.volumes] if deployment_data.spec.template.spec.volumes else []},
               'replica_sets': sorted(replica_sets, key=lambda x: x['name'], reverse=True),
               'events': sorted(events, key=lambda x: x['last_seen'], reverse=True)}
    return details


def get_stateful_sets(namespace="all"):
    if not apps_v1: init_k8s_client()
    if namespace == "all":
        items = apps_v1.list_stateful_set_for_all_namespaces().items
    else:
        items = apps_v1.list_namespaced_stateful_set(namespace).items
    return [{'name': item.metadata.name, 'namespace': item.metadata.namespace,
             'ready': f"{item.status.ready_replicas or 0}/{item.spec.replicas}",
             'age': _format_age(item.metadata.creation_timestamp)} for item in items]


def get_stateful_set_details(name, namespace):
    """
    Gets detailed, formatted information for a specific StatefulSet.
    """
    if not apps_v1 or not core_v1:
        init_k8s_client()

    sts_data = apps_v1.read_namespaced_stateful_set(name=name, namespace=namespace)
    events = []
    try:
        field_selector = f"involvedObject.uid={sts_data.metadata.uid}"
        event_list = core_v1.list_namespaced_event(namespace=namespace, field_selector=field_selector)
        events = [{'last_seen': item.last_timestamp.strftime("%Y-%m-%d %H:%M:%S") if item.last_timestamp else 'N/A', 'type': item.type, 'reason': item.reason, 'message': item.message} for item in event_list.items]
    except client.ApiException as e:
        print(f"Could not fetch events for StatefulSet {name}: {e}")

    details = {
        'name': sts_data.metadata.name,
        'namespace': sts_data.metadata.namespace,
        'creation_timestamp': sts_data.metadata.creation_timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        'labels': sts_data.metadata.labels,
        'owner_references': [{'kind': o.kind, 'name': o.name} for o in sts_data.metadata.owner_references] if sts_data.metadata.owner_references else [],
        'replicas_status': {
            'desired': sts_data.spec.replicas,
            'current': sts_data.status.current_replicas or 0,
            'ready': sts_data.status.ready_replicas or 0,
        },
        'pod_template': {
            'containers': [{'name': c.name, 'image': c.image} for c in sts_data.spec.template.spec.containers],
        },
        'events': sorted(events, key=lambda x: x['last_seen'], reverse=True)
    }
    return details


def get_daemon_sets(namespace="all"):
    if not apps_v1: init_k8s_client()
    if namespace == "all":
        items = apps_v1.list_daemon_set_for_all_namespaces().items
    else:
        items = apps_v1.list_namespaced_daemon_set(namespace).items
    return [{'name': item.metadata.name, 'namespace': item.metadata.namespace,
             'desired': item.status.desired_number_scheduled, 'current': item.status.current_number_scheduled,
             'ready': item.status.number_ready, 'age': _format_age(item.metadata.creation_timestamp)} for item in items]


def get_daemon_set_details(name, namespace):
    """
    Gets detailed, formatted information for a specific DaemonSet.
    """
    if not apps_v1 or not core_v1:
        init_k8s_client()

    ds_data = apps_v1.read_namespaced_daemon_set(name=name, namespace=namespace)
    events = []
    try:
        field_selector = f"involvedObject.uid={ds_data.metadata.uid}"
        event_list = core_v1.list_namespaced_event(namespace=namespace, field_selector=field_selector)
        events = [{'last_seen': item.last_timestamp.strftime("%Y-%m-%d %H:%M:%S") if item.last_timestamp else 'N/A', 'type': item.type, 'reason': item.reason, 'message': item.message} for item in event_list.items]
    except client.ApiException as e:
        print(f"Could not fetch events for DaemonSet {name}: {e}")

    details = {
        'name': ds_data.metadata.name,
        'namespace': ds_data.metadata.namespace,
        'creation_timestamp': ds_data.metadata.creation_timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        'labels': ds_data.metadata.labels,
        'owner_references': [{'kind': o.kind, 'name': o.name} for o in ds_data.metadata.owner_references] if ds_data.metadata.owner_references else [],
        'status': {
            'current': ds_data.status.current_number_scheduled,
            'desired': ds_data.status.desired_number_scheduled,
            'ready': ds_data.status.number_ready,
        },
        'pod_template': {
            'containers': [{'name': c.name, 'image': c.image} for c in ds_data.spec.template.spec.containers],
        },
        'events': sorted(events, key=lambda x: x['last_seen'], reverse=True)
    }
    return details


def get_replica_sets(namespace="all"):
    if not apps_v1: init_k8s_client()
    if namespace == "all":
        items = apps_v1.list_replica_set_for_all_namespaces().items
    else:
        items = apps_v1.list_namespaced_replica_set(namespace).items
    return [{'name': item.metadata.name, 'namespace': item.metadata.namespace, 'desired': item.spec.replicas,
             'current': item.status.replicas, 'ready': item.status.ready_replicas or 0,
             'age': _format_age(item.metadata.creation_timestamp)} for item in items]


def get_replica_set_details(name, namespace):
    """
    Gets detailed, formatted information for a specific ReplicaSet,
    including its events.
    """
    if not apps_v1 or not core_v1:
        init_k8s_client()

    # Get the main ReplicaSet object
    rs_data = apps_v1.read_namespaced_replica_set(name=name, namespace=namespace)

    # Get events for this ReplicaSet using its UID
    events = []
    try:
        field_selector = f"involvedObject.uid={rs_data.metadata.uid}"
        event_list = core_v1.list_namespaced_event(namespace=namespace, field_selector=field_selector)
        events = [{
            'last_seen': item.last_timestamp.strftime("%Y-%m-%d %H:%M:%S") if item.last_timestamp else 'N/A',
            'type': item.type,
            'reason': item.reason,
            'message': item.message
        } for item in event_list.items]
    except client.ApiException as e:
        print(f"Could not fetch events for ReplicaSet {name}: {e}")

    # Format the final details dictionary
    details = {
        'name': rs_data.metadata.name,
        'namespace': rs_data.metadata.namespace,
        'creation_timestamp': rs_data.metadata.creation_timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        'labels': rs_data.metadata.labels,
        'annotations': rs_data.metadata.annotations,
        'owner_references': [{'kind': o.kind, 'name': o.name} for o in
                             rs_data.metadata.owner_references] if rs_data.metadata.owner_references else [],
        'replicas_status': {
            'desired': rs_data.spec.replicas,
            'current': rs_data.status.replicas or 0,
            'ready': rs_data.status.ready_replicas or 0,
        },
        'pod_template': {
            'labels': rs_data.spec.template.metadata.labels,
            'containers': [{
                'name': c.name,
                'image': c.image,
                'ports': [p.to_dict() for p in c.ports] if c.ports else [],
                'env': [e.to_dict() for e in c.env] if c.env else []
            } for c in rs_data.spec.template.spec.containers],
        },
        'events': sorted(events, key=lambda x: x['last_seen'], reverse=True)
    }
    return details
# --- BATCH V1 RESOURCES ---

def get_jobs(namespace="all"):
    if not batch_v1: init_k8s_client()
    if namespace == "all":
        items = batch_v1.list_job_for_all_namespaces().items
    else:
        items = batch_v1.list_namespaced_job(namespace).items
    return [{'name': item.metadata.name, 'namespace': item.metadata.namespace,
             'completions': f"{item.status.succeeded or 0}/{item.spec.completions}",
             'age': _format_age(item.metadata.creation_timestamp)} for item in items]


def get_job_details(name, namespace):
    """
    Gets detailed, formatted information for a specific Job,
    including its pods and events.
    """
    if not batch_v1 or not core_v1:
        init_k8s_client()

    job_data = batch_v1.read_namespaced_job(name=name, namespace=namespace)

    # Get events for this Job
    events = []
    try:
        field_selector = f"involvedObject.uid={job_data.metadata.uid}"
        event_list = core_v1.list_namespaced_event(namespace=namespace, field_selector=field_selector)
        events = [{'last_seen': item.last_timestamp.strftime("%Y-%m-%d %H:%M:%S") if item.last_timestamp else 'N/A',
                   'type': item.type, 'reason': item.reason, 'message': item.message} for item in event_list.items]
    except client.ApiException as e:
        print(f"Could not fetch events for Job {name}: {e}")

    # Get pods created by this Job
    pods = []
    try:
        pod_list = core_v1.list_namespaced_pod(namespace=namespace, label_selector=f"job-name={name}")
        for pod in pod_list.items:
            # Double-check owner reference to be sure
            if pod.metadata.owner_references and pod.metadata.owner_references[0].uid == job_data.metadata.uid:
                pods.append({'name': pod.metadata.name, 'status': pod.status.phase})
    except client.ApiException as e:
        print(f"Could not fetch pods for Job {name}: {e}")

    details = {
        'name': job_data.metadata.name,
        'namespace': job_data.metadata.namespace,
        'creation_timestamp': job_data.metadata.creation_timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        'labels': job_data.metadata.labels,
        'owner_references': [{'kind': o.kind, 'name': o.name} for o in
                             job_data.metadata.owner_references] if job_data.metadata.owner_references else [],
        'spec': {
            'completions': job_data.spec.completions,
            'parallelism': job_data.spec.parallelism
        },
        'status': {
            'succeeded': job_data.status.succeeded or 0,
            'failed': job_data.status.failed or 0,
            'active': job_data.status.active or 0,
        },
        'pods': pods,
        'events': sorted(events, key=lambda x: x['last_seen'], reverse=True)
    }
    return details


def get_cron_jobs(namespace="all"):
    if not batch_v1: init_k8s_client()
    if namespace == "all":
        items = batch_v1.list_cron_job_for_all_namespaces().items
    else:
        items = batch_v1.list_namespaced_cron_job(namespace).items
    return [{'name': item.metadata.name, 'namespace': item.metadata.namespace, 'schedule': item.spec.schedule,
             'suspend': item.spec.suspend, 'active': len(item.status.active) if item.status.active else 0,
             'age': _format_age(item.metadata.creation_timestamp)} for item in items]


def get_cron_job_details(name, namespace):
    if not batch_v1: init_k8s_client()
    return batch_v1.read_namespaced_cron_job(name=name, namespace=namespace).to_dict()


# --- NETWORKING V1 RESOURCES ---

def get_ingresses(namespace="all"):
    if not networking_v1: init_k8s_client()
    if namespace == "all":
        items = networking_v1.list_ingress_for_all_namespaces().items
    else:
        items = networking_v1.list_namespaced_ingress(namespace).items
    return [{'name': item.metadata.name, 'namespace': item.metadata.namespace, 'class': item.spec.ingress_class_name,
             'hosts': ", ".join([rule.host for rule in item.spec.rules]) if item.spec.rules else '',
             'age': _format_age(item.metadata.creation_timestamp)} for item in items]


def get_ingress_details(name, namespace):
    if not networking_v1: init_k8s_client()
    return networking_v1.read_namespaced_ingress(name=name, namespace=namespace).to_dict()


# --- OTHER RESOURCES ---

def get_used_images():
    if not core_v1: init_k8s_client()
    # ... (rest of function is unchanged)
    all_pods = core_v1.list_pod_for_all_namespaces(watch=False)
    images = set()
    for pod in all_pods.items:
        for container in pod.spec.containers:
            images.add(container.image)
    return sorted(list(images))