import json

from django.http import HttpResponseBadRequest, JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_protect
from .models import PortScan, PortScanResult, NetworkDiagram
from django.contrib.auth.forms import UserCreationForm
from django.contrib import messages
import platform
import socket
import subprocess
import time
import ipaddress

def site_register(request):
    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect("dashboard")
    else:
        form = UserCreationForm()
    return render(request, "register.html", {"form": form})

@login_required
def scan_history(request):
    scans = (
        PortScan.objects
        .filter(user=request.user)
        .order_by("-created_at")
        .prefetch_related("results")
    )
    return render(request, "history.html", {"scans": scans})

@login_required
def diagram_list(request):
    diagrams = NetworkDiagram.objects.filter(user=request.user).order_by("-updated_at")
    if request.method == "POST":
        name = request.POST.get("name", "New Diagram").strip() or "New Diagram"
        d = NetworkDiagram.objects.create(user=request.user, name=name, data={"nodes": [], "edges": []})
        return redirect("diagram_editor", pk=d.pk)
    return render(request, "list.html", {"diagrams": diagrams})

@login_required
def diagram_editor(request, pk: int):
    diagram = get_object_or_404(NetworkDiagram, pk=pk, user=request.user)
    return render(request, "editor.html", {"diagram": diagram})

@login_required
@require_POST
@csrf_protect
def diagram_save(request, pk: int):
    diagram = get_object_or_404(NetworkDiagram, pk=pk, user=request.user)
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except Exception:
        return HttpResponseBadRequest("Invalid JSON")

    # Minimal validation
    nodes = payload.get("nodes", [])
    edges = payload.get("edges", [])
    if not isinstance(nodes, list) or not isinstance(edges, list):
        return HttpResponseBadRequest("nodes/edges must be lists")

    diagram.data = {"nodes": nodes, "edges": edges}
    diagram.save(update_fields=["data", "updated_at"])
    return JsonResponse({"ok": True, "updated_at": diagram.updated_at.isoformat()})
def site_login(request):
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect("dashboard")
        messages.error(request, "Invalid username or password.")
    return render(request, "login.html", {})

def site_logout(request):
    logout(request)
    return redirect("dashboard")

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
        # On many Linux systems this binary is `traceroute`
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

    # Compute usable host count and first/last usable
    if isinstance(net, ipaddress.IPv4Network) and net.prefixlen <= 30:
        usable_hosts = max(total - 2, 0)
        first_host_int = int(net.network_address) + 1
        last_host_int = int(net.broadcast_address) - 1
        first_host = str(ipaddress.IPv4Address(first_host_int))
        last_host = str(ipaddress.IPv4Address(last_host_int))
    else:
        # For /31, /32, and IPv6, treat all as "usable"
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
            profile = request.POST.get("profile", "quick")
            notes = request.POST.get("notes", "").strip()
            save = request.POST.get("save") == "1"

            if target:
                ports = parse_ports(ports_str)
                try:
                    scan_results = scan_ports(target, ports)
                    context["results"] = scan_results

                    # Save only if user is logged in and checkbox checked
                    if save and request.user.is_authenticated:
                        scan = PortScan.objects.create(
                            user=request.user,
                            target=target,
                            ports=ports_str,
                            profile=profile,
                            notes=notes,
                        )
                        PortScanResult.objects.bulk_create([
                            PortScanResult(
                                scan=scan,
                                port=r["port"],
                                protocol=r["protocol"],
                                state=r["state"],
                                service=r["service"],
                                latency_ms=r["latency"],
                            )
                            for r in scan_results
                        ])

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