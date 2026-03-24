import subprocess
import ipaddress

import socket


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't actually send packets
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    return local_ip


def is_external_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_reserved)
    except ValueError:
        return False


def get_tshark_interfaces():
    result = subprocess.check_output(["tshark", "-D"], text=True)
    interfaces = {}

    for line in result.splitlines():
        # Example: "5. Wi-Fi"
        if ". " in line:
            idx, name = line.split(". ", 1)
            interfaces[idx.strip()] = name.strip()

    return interfaces


def find_active_interface():
    local_ip = get_local_ip()
    interfaces = get_tshark_interfaces()

    for idx in interfaces:
        try:
            # Ask tshark for addresses on this interface
            cmd = [
                "tshark",
                "-i",
                idx,
                "-c",
                "5",
                "-f",
                "ip",
                "-T",
                "fields",
                "-e",
                "ip.src",
                "-e",
                "ip.dst",
            ]
            output = subprocess.check_output(
                cmd,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=3,
            )

            if local_ip in output:
                return idx

        except Exception:
            continue

    raise LookupError("Unable to gather active interface.")


def get_external_ips(duration: int = 30):
    """
    Captures traffic for `duration` seconds and returns a set of external source IPs.

    Args:
        duration: capture time in seconds

    Returns:
        set of external IP strings
    """

    # Build capture filter
    local_ip = get_local_ip()
    capture_filter = f"ip dst host {local_ip}"

    interface = find_active_interface()

    cmd = [
        "tshark",
        "-i",
        interface,
        "-a",
        f"duration:{duration}",
        "-f",
        capture_filter,
        "-T",
        "fields",
        "-e",
        "ip.src",
    ]

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    external_ips = set()

    for line in process.stdout:
        ip = line.strip()
        # if ip and is_external_ip(ip):
        external_ips.add(ip)

    process.wait()

    return external_ips


if __name__ == "__main__":
    get_external_ips()
