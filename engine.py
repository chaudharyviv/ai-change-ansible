"""
engine.py — AI Change Governance Platform (Ansible Edition)
============================================================
Architecture:
  Streamlit Cloud ──SSH──▶ Control Node (Oracle VM #1)
                               └─ ansible-playbook ──▶ Managed Node (Oracle VM #2)
                                                            └─ health JSON written
                               └─ engine.py reads JSON back over SSH
                               └─ Claude AI validates
                               └─ ServiceNow updated

Streamlit Secrets required:
  ANTHROPIC_API_KEY
  SERVICENOW_INSTANCE       e.g. dev12345.service-now.com
  SERVICENOW_USER
  SERVICENOW_PASS
  CONTROL_SSH_HOST          Control Node public IP  (Oracle VM #1)
  CONTROL_SSH_USER          e.g. opc
  CONTROL_SSH_PRIVATE_KEY   Full PEM contents (multiline)
"""

import io
import json
import os
import time
import requests
import anthropic
import paramiko
import streamlit as st
from datetime import datetime


# ── Secrets helper ────────────────────────────────────────────────────────────

def _secret(key: str) -> str:
    try:
        return st.secrets[key]
    except Exception:
        return os.getenv(key, "")


# ── Paths on the Control Node ─────────────────────────────────────────────────

PLAYBOOK_DIR  = "~/ansible_project/playbooks"
INVENTORY     = f"{PLAYBOOK_DIR}/inventory.ini"
PRE_JSON      = "/tmp/pre_health.json"
POST_JSON     = "/tmp/post_health.json"
CHANGE_JSON   = "/tmp/change_applied.json"


# ══════════════════════════════════════════════════════════════════════════════
# SSH — connect to Control Node
# ══════════════════════════════════════════════════════════════════════════════

def _ssh() -> paramiko.SSHClient:
    """Return authenticated SSH client connected to the Control Node."""
    host    = _secret("CONTROL_SSH_HOST")
    user    = _secret("CONTROL_SSH_USER")
    pem_str = _secret("CONTROL_SSH_PRIVATE_KEY")

    if not all([host, user, pem_str]):
        raise RuntimeError(
            "SSH secrets missing. Add CONTROL_SSH_HOST, CONTROL_SSH_USER, "
            "CONTROL_SSH_PRIVATE_KEY to Streamlit secrets."
        )

    pkey   = paramiko.RSAKey.from_private_key(io.StringIO(pem_str))
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, username=user, pkey=pkey, timeout=15)
    return client


def _run(cmd: str, timeout: int = 300) -> tuple[str, str, int]:
    """
    Run a command on the Control Node.
    Returns (stdout, stderr, exit_code).
    """
    client = _ssh()
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out  = stdout.read().decode().strip()
    err  = stderr.read().decode().strip()
    code = stdout.channel.recv_exit_status()
    client.close()
    return out, err, code


def _read_remote_json(remote_path: str) -> dict:
    """
    SCP a JSON file from the Control Node back to Streamlit and parse it.
    The JSON was written there by the Ansible playbook on the Managed Node
    and pulled back by the Control Node post-run.
    """
    client = _ssh()
    sftp   = client.open_sftp()
    buf    = io.BytesIO()
    sftp.getfo(remote_path, buf)
    sftp.close()
    client.close()
    buf.seek(0)
    return json.loads(buf.read().decode())


# ══════════════════════════════════════════════════════════════════════════════
# ANSIBLE runner
# ══════════════════════════════════════════════════════════════════════════════

def _ansible(playbook: str, extra_vars: dict | None = None, timeout: int = 300) -> dict:
    """
    Run an ansible-playbook command on the Control Node.
    Returns structured result with stdout, stderr, rc, and parsed JSON output.
    """
    ev_str = ""
    if extra_vars:
        kv     = " ".join(f"{k}={v}" for k, v in extra_vars.items())
        ev_str = f"-e \"{kv}\""

    cmd = (
        f"ansible-playbook {PLAYBOOK_DIR}/{playbook} "
        f"-i {INVENTORY} {ev_str} 2>&1"
    )

    out, err, rc = _run(cmd, timeout=timeout)

    return {
        "playbook": playbook,
        "rc":       rc,
        "stdout":   out,
        "stderr":   err,
        "success":  rc == 0,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 — ServiceNow: create_change()
# ══════════════════════════════════════════════════════════════════════════════

def _sn():
    instance = _secret("SERVICENOW_INSTANCE")
    user     = _secret("SERVICENOW_USER")
    password = _secret("SERVICENOW_PASS")
    if not all([instance, user, password]):
        raise RuntimeError("ServiceNow secrets missing.")
    return instance, user, password


def create_change() -> dict:
    instance, user, password = _sn()
    r = requests.post(
        f"https://{instance}/api/now/table/change_request",
        auth=(user, password),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        json={
            "short_description": "AI-Governed Linux Change (Ansible)",
            "description":       "Automated Ansible pre/post health validation via Claude AI.",
            "type":              "normal",
            "state":             "-5",
        },
        timeout=15,
    )
    r.raise_for_status()
    result = r.json()["result"]
    return {"number": result["number"], "sys_id": result["sys_id"]}


def update_change(sys_id: str, notes: str, state: str | None = None) -> None:
    instance, user, password = _sn()
    payload = {"work_notes": notes}
    if state:
        payload["state"] = state
    r = requests.patch(
        f"https://{instance}/api/now/table/change_request/{sys_id}",
        auth=(user, password),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        json=payload,
        timeout=15,
    )
    r.raise_for_status()


def attach_file(sys_id: str, filename: str, data: dict) -> None:
    instance, user, password = _sn()
    r = requests.post(
        f"https://{instance}/api/now/attachment/file"
        f"?table_name=change_request&table_sys_id={sys_id}&file_name={filename}",
        auth=(user, password),
        headers={"Content-Type": "application/octet-stream", "Accept": "application/json"},
        data=json.dumps(data, indent=2).encode(),
        timeout=15,
    )
    r.raise_for_status()


# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 — pre_health_check()
# ══════════════════════════════════════════════════════════════════════════════

def pre_health_check() -> dict:
    """
    Trigger pre_health_check.yml on the Managed Node via the Control Node.
    Pull the resulting JSON back to Streamlit.
    """
    result = _ansible("pre_health_check.yml")
    if not result["success"]:
        raise RuntimeError(
            f"pre_health_check.yml failed (rc={result['rc']}):\n{result['stdout']}"
        )

    # Pull the JSON the playbook wrote on the Managed Node
    # (Ansible fetched it to /tmp/pre_health.json on the control node via fetch module)
    health = _read_remote_json(PRE_JSON)
    health["_ansible_run"] = result
    return health


# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 — apply_change()
# ══════════════════════════════════════════════════════════════════════════════

def apply_change(scenario: str) -> dict:
    """
    Trigger apply_change.yml on the Managed Node with the chosen scenario.
    scenario must be one of: small_disk | large_disk | cpu_stress | stop_service
    """
    scenario_map = {
        "Small Disk (PASS)":      "small_disk",
        "Large Disk Fill (FAIL)": "large_disk",
        "CPU Stress (FAIL)":      "cpu_stress",
        "Stop a Service (FAIL)":  "stop_service",
    }
    key = scenario_map.get(scenario, scenario)

    result = _ansible("apply_change.yml", extra_vars={"scenario": key}, timeout=360)
    if not result["success"]:
        raise RuntimeError(
            f"apply_change.yml failed (rc={result['rc']}):\n{result['stdout']}"
        )

    change_info = _read_remote_json(CHANGE_JSON)
    change_info["_ansible_run"] = result
    return change_info


# ══════════════════════════════════════════════════════════════════════════════
# STEP 4 — post_health_check()
# ══════════════════════════════════════════════════════════════════════════════

def post_health_check() -> dict:
    """
    Trigger post_health_check.yml on the Managed Node via the Control Node.
    Pull the resulting JSON back to Streamlit.
    """
    result = _ansible("post_health_check.yml")
    if not result["success"]:
        raise RuntimeError(
            f"post_health_check.yml failed (rc={result['rc']}):\n{result['stdout']}"
        )

    health = _read_remote_json(POST_JSON)
    health["_ansible_run"] = result
    return health


# ══════════════════════════════════════════════════════════════════════════════
# STEP 5 — compare(pre, post)
# ══════════════════════════════════════════════════════════════════════════════

def compare(pre: dict, post: dict) -> dict:
    """Compute structured diff between pre and post Ansible health snapshots."""

    def safe_int(val, default=0):
        try:
            return int(val)
        except Exception:
            return default

    def safe_float(val, default=0.0):
        try:
            return float(val)
        except Exception:
            return default

    pre_root  = safe_int(pre.get("disk", {}).get("root", {}).get("used_percent", 0))
    post_root = safe_int(post.get("disk", {}).get("root", {}).get("used_percent", 0))
    pre_tmp   = safe_int(pre.get("disk", {}).get("tmp",  {}).get("used_percent", 0))
    post_tmp  = safe_int(post.get("disk", {}).get("tmp",  {}).get("used_percent", 0))

    pre_load  = safe_float(pre.get("load_1m",  0))
    post_load = safe_float(post.get("load_1m", 0))
    pre_mem   = safe_int(pre.get("memory",  {}).get("used_percent", 0))
    post_mem  = safe_int(post.get("memory", {}).get("used_percent", 0))

    # Service changes
    pre_svcs  = pre.get("services",  {})
    post_svcs = post.get("services", {})
    svc_changes = {
        svc: {"before": pre_svcs.get(svc, "unknown"), "after": post_svcs.get(svc, "unknown")}
        for svc in set(pre_svcs) | set(post_svcs)
        if pre_svcs.get(svc) != post_svcs.get(svc)
    }

    return {
        "disk_root_before":    pre_root,
        "disk_root_after":     post_root,
        "disk_root_delta":     post_root - pre_root,
        "disk_tmp_before":     pre_tmp,
        "disk_tmp_after":      post_tmp,
        "disk_tmp_delta":      post_tmp - pre_tmp,
        "load_before":         pre_load,
        "load_after":          post_load,
        "load_delta":          round(post_load - pre_load, 2),
        "memory_before":       pre_mem,
        "memory_after":        post_mem,
        "memory_delta":        post_mem - pre_mem,
        "service_changes":     svc_changes,
        "top_processes_post":  post.get("top_processes", ""),
        "pre_warnings":        pre.get("warnings", []),
    }


# ══════════════════════════════════════════════════════════════════════════════
# STEP 6 — risk_score(diff)
# ══════════════════════════════════════════════════════════════════════════════

def risk_score(diff: dict) -> dict:
    score, reasons = 0, []

    if diff["disk_root_after"] > 90:
        score += 50;  reasons.append(f"Root disk critical: {diff['disk_root_after']}%")
    elif diff["disk_root_after"] > 80:
        score += 25;  reasons.append(f"Root disk high: {diff['disk_root_after']}%")

    if diff["disk_tmp_after"] > 90:
        score += 35;  reasons.append(f"/tmp critical: {diff['disk_tmp_after']}%")
    elif diff["disk_tmp_after"] > 75:
        score += 15;  reasons.append(f"/tmp elevated: {diff['disk_tmp_after']}%")

    if diff["load_after"] > 8:
        score += 40;  reasons.append(f"Load very high: {diff['load_after']}")
    elif diff["load_after"] > 3:
        score += 20;  reasons.append(f"Load elevated: {diff['load_after']}")

    if diff["disk_root_delta"] > 20:
        score += 20;  reasons.append(f"Root disk grew +{diff['disk_root_delta']}%")
    elif diff["disk_root_delta"] > 10:
        score += 10;  reasons.append(f"Root disk grew +{diff['disk_root_delta']}%")

    if diff["disk_tmp_delta"] > 15:
        score += 15;  reasons.append(f"/tmp grew +{diff['disk_tmp_delta']}%")

    failed_svcs = [
        f"{s}: {v['before']} → {v['after']}"
        for s, v in diff["service_changes"].items()
        if v["after"] in ("inactive", "failed", "unknown")
    ]
    if failed_svcs:
        score += 30 * len(failed_svcs)
        reasons.append(f"Service failures: {', '.join(failed_svcs)}")

    score = min(score, 100)

    if score < 20:   severity = "Low"
    elif score < 50: severity = "Medium"
    elif score < 80: severity = "High"
    else:            severity = "Critical"

    return {"score": score, "severity": severity, "reasons": reasons}


# ══════════════════════════════════════════════════════════════════════════════
# STEP 7 — ai_validate()
# ══════════════════════════════════════════════════════════════════════════════

def ai_validate(pre: dict, post: dict, diff: dict, risk: dict, change_info: dict) -> dict:
    """
    Send Ansible playbook outputs + diff + risk model to Claude.
    Claude parses the structured JSON, validates the change, and returns
    PASS or FAIL with a full SRE-style analysis for ServiceNow work notes.
    """
    api_key = _secret("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY missing from Streamlit secrets.")

    client = anthropic.Anthropic(api_key=api_key)

    system = """You are a senior Site Reliability Engineer validating a Linux system change.
You receive structured output from Ansible health-check playbooks and a risk model.
You reason carefully from the data, write clear ServiceNow-ready work notes,
and always end with a definitive PASS or FAIL verdict. You never hedge."""

    prompt = f"""A change has been applied to a managed Linux server.
The health data below was collected by Ansible playbooks before and after the change.

## Pre-Change Ansible Health Output
```json
{json.dumps({k: v for k, v in pre.items() if k != "_ansible_run"}, indent=2)}
```

## Post-Change Ansible Health Output
```json
{json.dumps({k: v for k, v in post.items() if k != "_ansible_run"}, indent=2)}
```

## Computed Diff (Python)
```json
{json.dumps(diff, indent=2)}
```

## Risk Model Score
```json
{json.dumps(risk, indent=2)}
```

## Change Request
ServiceNow Change: {change_info.get('number', 'N/A')}

---

Your response must contain these sections:

### 1. DISK ANALYSIS
Assess root and /tmp disk usage. Are levels safe? Is the delta expected?

### 2. LOAD & MEMORY ANALYSIS
Is load average acceptable? Any memory pressure introduced?

### 3. SERVICE ANALYSIS
List any services that changed state. Are failures critical?

### 4. ANSIBLE PLAYBOOK ASSESSMENT
Did the playbooks run cleanly? Any task-level concerns?

### 5. RISK VERDICT
Do you agree with the risk score of {risk['score']}/100 ({risk['severity']})?

### 6. SERVICENOW WORK NOTES
Write 3-5 sentences suitable for pasting directly into ServiceNow work notes.
Professional, factual, past-tense.

### 7. FINAL VERDICT
End with exactly one of:
`VALIDATION: PASS`
`VALIDATION: FAIL`

If FAIL — list the specific issues that must be resolved before closing the change."""

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1500,
        system=system,
        messages=[{"role": "user", "content": prompt}],
    )

    text    = response.content[0].text
    verdict = "PASS" if "VALIDATION: PASS" in text.upper() else "FAIL"

    # Extract ServiceNow work notes section
    sn_notes = text
    if "### 6. SERVICENOW WORK NOTES" in text:
        try:
            sn_notes = text.split("### 6. SERVICENOW WORK NOTES")[1].split("### 7.")[0].strip()
        except Exception:
            sn_notes = text[:500]

    return {
        "verdict":      verdict,
        "full_analysis": text,
        "sn_notes":     sn_notes,
        "model":        response.model,
        "tokens":       response.usage.input_tokens + response.usage.output_tokens,
    }


# ══════════════════════════════════════════════════════════════════════════════
# CLEANUP — runs ansible cleanup or direct remote kill
# ══════════════════════════════════════════════════════════════════════════════

def cleanup(scenario: str) -> str:
    """Clean up temp files and processes left by the change scenario."""
    cmds = [
        "rm -f /tmp/ai_small.bin /tmp/ai_large.bin",
        "if [ -f /tmp/stress_pids.txt ]; then kill -9 $(cat /tmp/stress_pids.txt) 2>/dev/null; rm -f /tmp/stress_pids.txt; fi",
        "rm -f /tmp/pre_health.json /tmp/post_health.json /tmp/change_applied.json",
    ]
    if scenario == "Stop a Service (FAIL)":
        cmds.append("sudo systemctl start chronyd 2>/dev/null || true")

    results = []
    for cmd in cmds:
        out, err, rc = _run(cmd, timeout=30)
        results.append({"cmd": cmd, "rc": rc, "out": out})

    return results
