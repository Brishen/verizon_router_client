import os
import kopf
import logging

from .cr1000a import VerizonRouterClient

# Retrieve settings from environment
ROUTER_BASE_URL = os.environ.get("ROUTER_BASE_URL", "https://192.168.1.1")
ROUTER_TLS_HOSTNAME = os.environ.get("ROUTER_TLS_HOSTNAME", "mynetworksettings.com")
ROUTER_USERNAME = os.environ.get("ROUTER_USERNAME", "admin")
ROUTER_PASSWORD = os.environ.get("ROUTER_PASSWORD")

logger = logging.getLogger(__name__)

def get_client() -> VerizonRouterClient:
    """Helper to initialize and authenticate the router client."""
    if not ROUTER_PASSWORD:
        raise ValueError("ROUTER_PASSWORD environment variable is not set")

    client = VerizonRouterClient(
        base_url=ROUTER_BASE_URL,
        tls_hostname=ROUTER_TLS_HOSTNAME,
    )
    # Perform login
    client.login(ROUTER_USERNAME, ROUTER_PASSWORD)
    return client

@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_):
    """Operator startup configuration."""
    if not ROUTER_PASSWORD:
        logger.error("ROUTER_PASSWORD is not set. Operator may fail to interact with the router.")
    else:
        logger.info(f"Operator starting. Connecting to {ROUTER_BASE_URL} as {ROUTER_USERNAME}")

# --- FiosDnsRecord Handlers ---

@kopf.on.create("network.verizon.com", "v1alpha1", "fiosdnsrecords")
@kopf.on.update("network.verizon.com", "v1alpha1", "fiosdnsrecords")
def dns_record_upsert(spec, name, logger, **kwargs):
    """Create or update a DNS record on the router."""
    hostname = spec.get("hostname")
    ip = spec.get("ip")

    if not hostname or not ip:
        raise kopf.PermanentError(f"Both 'hostname' and 'ip' must be set for {name}")

    client = get_client()

    # The router UI manages existing slots, or we add a new one.
    # To keep it simple, we can remove the existing record by hostname and add it back.
    # This ensures an update handles both a new IP or an existing IP cleanly.
    logger.info(f"Upserting DNS record: {hostname} -> {ip}")

    # Remove existing entries for this hostname to avoid duplicates
    removed = client.remove_dns_ipv4_by_hostname(hostname, remove_all=True)
    if removed:
        logger.info(f"Removed existing DNS records for {hostname} at slots {removed}")

    # Add the new record
    slot = client.add_dns_ipv4(hostname, ip)
    logger.info(f"Added DNS record for {hostname} at slot {slot}")

    return {"status": "upserted", "slot": slot, "hostname": hostname, "ip": ip}


@kopf.on.delete("network.verizon.com", "v1alpha1", "fiosdnsrecords")
def dns_record_delete(spec, name, logger, **kwargs):
    """Delete a DNS record from the router."""
    hostname = spec.get("hostname")

    if not hostname:
        logger.warning(f"No 'hostname' found in {name} spec. Skipping deletion.")
        return

    client = get_client()

    logger.info(f"Deleting DNS record: {hostname}")
    removed = client.remove_dns_ipv4_by_hostname(hostname, remove_all=True)
    if removed:
        logger.info(f"Removed DNS records for {hostname} at slots {removed}")
    else:
        logger.info(f"No existing DNS records found for {hostname}")

# --- FiosPortForward Handlers ---

@kopf.on.create("network.verizon.com", "v1alpha1", "fiosportforwards")
@kopf.on.update("network.verizon.com", "v1alpha1", "fiosportforwards")
def port_forward_upsert(spec, name, logger, **kwargs):
    """Create or update a Port Forwarding rule on the router."""
    rule_name = spec.get("name")
    private_ip = spec.get("private_ip")
    forward_port = spec.get("forward_port")
    dest_port = spec.get("dest_port")

    if not rule_name or not private_ip or not forward_port or not dest_port:
        raise kopf.PermanentError(f"Missing required fields (name, private_ip, forward_port, dest_port) for {name}")

    client = get_client()

    logger.info(f"Upserting Port Forwarding rule: {rule_name} ({forward_port} -> {private_ip}:{dest_port})")

    # To handle updates cleanly, remove existing rule if it matches by name
    # The router allows multiple rules with the same name, so we find and delete them
    settings = client.get_port_forwarding_settings()
    entries = settings.get("portforwardings", [])

    # We might have to get a new apply token for each operation
    token = client.get_apply_token()

    for entry in entries:
        if isinstance(entry, dict) and entry.get("name") == rule_name:
            entry_id = entry.get("id")
            if entry_id is not None:
                logger.info(f"Removing existing Port Forwarding rule '{rule_name}' with ID {entry_id}")
                client.remove_port_forward(rule_id=entry_id, token=token)

    # Add the new rule
    try:
        rule_id = client.add_port_forward(
            name=rule_name,
            private_ip=private_ip,
            forward_port=forward_port,
            dest_port=dest_port,
            token=token
        )
        logger.info(f"Added Port Forwarding rule '{rule_name}' with ID {rule_id}")
        return {"status": "upserted", "rule_id": rule_id, "name": rule_name}
    except Exception as e:
        logger.error(f"Failed to add Port Forwarding rule: {e}")
        raise kopf.TemporaryError(f"Failed to add Port Forwarding rule: {e}", delay=30)


@kopf.on.delete("network.verizon.com", "v1alpha1", "fiosportforwards")
def port_forward_delete(spec, name, logger, **kwargs):
    """Delete a Port Forwarding rule from the router."""
    rule_name = spec.get("name")

    if not rule_name:
        logger.warning(f"No 'name' found in {name} spec. Skipping deletion.")
        return

    client = get_client()

    logger.info(f"Deleting Port Forwarding rule: {rule_name}")

    settings = client.get_port_forwarding_settings()
    entries = settings.get("portforwardings", [])

    token = client.get_apply_token()

    removed = False
    for entry in entries:
        if isinstance(entry, dict) and entry.get("name") == rule_name:
            entry_id = entry.get("id")
            if entry_id is not None:
                logger.info(f"Removing Port Forwarding rule '{rule_name}' with ID {entry_id}")
                client.remove_port_forward(rule_id=entry_id, token=token)
                removed = True

    if not removed:
        logger.info(f"No existing Port Forwarding rules found for '{rule_name}'")
