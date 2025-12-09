from django.shortcuts import render
import platform
import socket
import subprocess
import time
import ipaddress

def parse_ports(ports_str: str):
    if not ports_str:
        return [80, 443]

    ports = set()
    for part in ports_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            try:
                start = int(start_s)
                end = int(end_s)
            except ValueError:
                continue
            if start > end:
                start, end = end, start
            for p in range(start, end + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            try:
                p = int(part)
            except ValueError:
                continue
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports) or [80, 443]


def scan_ports(host: str, ports, timeout: float = 0.5):
    results = []
    for port in ports:
        state = "closed"
        latency_ms = None
        service = ""
        start = time.perf_counter()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((host, port))
                state = "open"
        except (socket.timeout, OSError):
            state = "closed"
        finally:
            latency_ms = int((time.perf_counter() - start) * 1000)

        try:
            service = socket.getservbyport(port, "tcp")
        except OSError:
            service = ""

        results.append(
            {
                "port": port,
                "protocol": "TCP",
                "state": state,
                "service": service,
                "latency": latency_ms,
            }
        )
    return results


def run_ping(target: str, count: int = 4):
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", str(count), target]
    else:
        cmd = ["ping", "-c", str(count), target]
    completed = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=10,
    )
    output = completed.stdout or completed.stderr
    return output.strip()


def run_traceroute(target: str, max_hops: int = 30):
    system = platform.system().lower()
    if system == "windows":
        cmd = ["tracert", "-h", str(max_hops), target]
    else:
        cmd = ["traceroute", "-m", str(max_hops), target]

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = completed.stdout or completed.stderr
        return output.strip()
    except FileNotFoundError:
        return "traceroute command not found on this system."
    except subprocess.TimeoutExpired:
        return "Traceroute timed out."


def calculate_subnet(cidr: str):
    net = ipaddress.ip_network(cidr, strict=False)
    total = net.num_addresses

    if isinstance(net, ipaddress.IPv4Network) and net.prefixlen <= 30:
        usable_hosts = max(total - 2, 0)
        first_host_int = int(net.network_address) + 1
        last_host_int = int(net.broadcast_address) - 1
        first_host = str(ipaddress.IPv4Address(first_host_int))
        last_host = str(ipaddress.IPv4Address(last_host_int))
    else:
        usable_hosts = total
        first_host = str(net.network_address)
        last_host = str(net.broadcast_address)

    return {
        "network": str(net.network_address),
        "broadcast": str(net.broadcast_address),
        "prefixlen": net.prefixlen,
        "total": total,
        "usable_hosts": usable_hosts,
        "first_host": first_host,
        "last_host": last_host,
    }


def do_dns_lookup(host: str):
    try:
        info = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        return {"host": host, "addresses": [], "error": str(e)}

    addresses = sorted({item[4][0] for item in info})
    return {"host": host, "addresses": addresses, "error": None}


def dashboard(request):
    context = {
        "results": None,
        "ping_output": None,
        "ping_error": None,
        "traceroute_output": None,
        "traceroute_error": None,
        "subnet": None,
        "subnet_error": None,
        "dns": None,
        "dns_error": None,
    }

    if request.method == "POST":
        tool = request.POST.get("tool")

        if tool == "port_scan":
            target = request.POST.get("target", "").strip()
            ports_str = request.POST.get("ports", "").strip()
            if target:
                ports = parse_ports(ports_str)
                try:
                    context["results"] = scan_ports(target, ports)
                except Exception as exc:
                    context["results"] = []
                    context["scan_error"] = str(exc)
            else:
                context["results"] = []

        elif tool == "ping":
            target = request.POST.get("target", "").strip()
            if target:
                try:
                    context["ping_output"] = run_ping(target)
                except Exception as exc:
                    context["ping_error"] = str(exc)

        elif tool == "traceroute":
            target = request.POST.get("target", "").strip()
            if target:
                try:
                    context["traceroute_output"] = run_traceroute(target)
                except Exception as exc:
                    context["traceroute_error"] = str(exc)

        elif tool == "subnet":
            cidr = request.POST.get("cidr", "").strip()
            if cidr:
                try:
                    context["subnet"] = calculate_subnet(cidr)
                except ValueError as exc:
                    context["subnet_error"] = str(exc)

        elif tool == "dns":
            host = request.POST.get("host", "").strip()
            if host:
                result = do_dns_lookup(host)
                if result["error"]:
                    context["dns_error"] = result["error"]
                else:
                    context["dns"] = result

    return render(request, "dashboard.html", context)