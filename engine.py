from __future__ import annotations

"""
engine.py — AI Change Governance Platform (GitHub Actions + OPENAI Edition)
"""

import io
import json
import os
import time
import zipfile
import requests
from openai import OpenAI
import streamlit as st
from datetime import datetime


# ── Secrets ───────────────────────────────────────────────────────────────────

def _secret(key):
    try:
        return st.secrets[key]
    except Exception:
        return os.getenv(key, "")


# ── Workflow IDs ──────────────────────────────────────────────────────────────
# Numeric IDs avoid 404s. Get yours:
# https://api.github.com/repos/OWNER/REPO/actions/workflows

_WORKFLOW_IDS = {
    "pre_health_check.yml":  "237876997",
    "apply_change.yml":      "237876994",
    "post_health_check.yml": "237876996",
    "cleanup.yml":           "237876995",
}


# ── GitHub helpers ────────────────────────────────────────────────────────────

def _gh_headers():
    token = _secret("GITHUB_PAT")
    if not token:
        raise RuntimeError("GITHUB_PAT missing from Streamlit secrets.")
    return {
        "Authorization":        f"token {token}",
        "Accept":               "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _repo():
    owner = _secret("GITHUB_OWNER")
    repo  = _secret("GITHUB_REPO")
    if not owner or not repo:
        raise RuntimeError("GITHUB_OWNER and GITHUB_REPO missing.")
    return f"{owner}/{repo}"


# ── GitHub Actions ────────────────────────────────────────────────────────────

def trigger_workflow(workflow_filename, inputs):
    repo        = _repo()
    headers     = _gh_headers()
    workflow_id = _WORKFLOW_IDS.get(workflow_filename, workflow_filename)
    before_ts   = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    r = requests.post(
        f"https://api.github.com/repos/{repo}/actions/workflows/{workflow_id}/dispatches",
        headers=headers,
        json={"ref": "main", "inputs": inputs},
        timeout=15,
    )
    if r.status_code != 204:
        raise RuntimeError(f"GitHub dispatch failed ({r.status_code}): {r.text}")

    time.sleep(5)
    return _find_run_id(workflow_id, before_ts)


def _find_run_id(workflow_id, created_after):
    repo    = _repo()
    headers = _gh_headers()

    for _ in range(15):
        r = requests.get(
            f"https://api.github.com/repos/{repo}/actions/workflows/{workflow_id}/runs",
            headers=headers,
            params={"per_page": 5},
            timeout=15,
        )
        r.raise_for_status()
        runs = r.json().get("workflow_runs", [])
        if runs:
            return str(runs[0]["id"])
        time.sleep(3)

    raise RuntimeError("Could not find workflow run after dispatch.")


def wait_for_workflow(run_id, timeout_seconds=600):
    repo     = _repo()
    headers  = _gh_headers()
    start    = time.time()
    progress = st.progress(0, text="GitHub Actions running...")

    while True:
        elapsed = round(time.time() - start)
        if elapsed > timeout_seconds:
            raise RuntimeError(f"Workflow timed out after {timeout_seconds}s.")

        r = requests.get(
            f"https://api.github.com/repos/{repo}/actions/runs/{run_id}",
            headers=headers,
            timeout=15,
        )
        r.raise_for_status()
        run        = r.json()
        status     = run.get("status")
        conclusion = run.get("conclusion")
        pct        = min(int(elapsed / timeout_seconds * 100), 95)

        progress.progress(
            pct,
            text=f"GitHub Actions: {status} ({elapsed}s) — [View]({run.get('html_url', '')})"
        )

        if status == "completed":
            progress.progress(100, text=f"Done: {conclusion}")
            run["elapsed_seconds"] = elapsed
            return run

        time.sleep(8)


def download_artifact(run_id, artifact_name):
    repo    = _repo()
    headers = _gh_headers()

    r = requests.get(
        f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/artifacts",
        headers=headers,
        timeout=15,
    )
    r.raise_for_status()
    artifacts = r.json().get("artifacts", [])

    target = next((a for a in artifacts if a["name"] == artifact_name), None)
    if not target:
        raise RuntimeError(
            f"Artifact '{artifact_name}' not found. "
            f"Available: {[a['name'] for a in artifacts]}"
        )

    dl = requests.get(target["archive_download_url"], headers=headers, timeout=30)
    dl.raise_for_status()

    with zipfile.ZipFile(io.BytesIO(dl.content)) as zf:
        json_files = [n for n in zf.namelist() if n.endswith(".json")]
        if not json_files:
            raise RuntimeError(f"No JSON in artifact '{artifact_name}'.")
        with zf.open(json_files[0]) as jf:
            return json.loads(jf.read().decode())


# ── ServiceNow ────────────────────────────────────────────────────────────────

# ── ServiceNow (Safe & Consistent) ───────────────────────────────────────────

def _sn():
    instance = _secret("SERVICENOW_INSTANCE")
    user     = _secret("SERVICENOW_USER")
    password = _secret("SERVICENOW_PASS")
    if not all([instance, user, password]):
        raise RuntimeError("ServiceNow secrets missing.")
    return instance, user, password


def create_change():
    """
    Always creates a NEW change and returns number + sys_id.
    """

    instance, user, password = _sn()

    payload = {
        "short_description":  "AI-Governed Linux Change (Ansible + GitHub Actions)",
        "description":        "Automated pre/post Ansible health validation via OPENAI.",
        "type":               "normal",
        "state":              "-1",  # New
        "assigned_to":        "admin",
        "planned_start_date": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "planned_end_date":   datetime.utcnow().strftime("%Y-%m-%d 23:59:59"),
    }

    r = requests.post(
        f"https://{instance}/api/now/table/change_request",
        auth=(user, password),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        json=payload,
        timeout=20,
    )
    r.raise_for_status()

    result = r.json()["result"]

    return {
        "number": result["number"],
        "sys_id": result["sys_id"],
        "state":  result.get("state"),
    }


def _get_change(sys_id):
    """
    Fetches change from ServiceNow to verify state before update.
    """

    instance, user, password = _sn()

    r = requests.get(
        f"https://{instance}/api/now/table/change_request/{sys_id}",
        auth=(user, password),
        headers={"Accept": "application/json"},
        timeout=20,
    )
    r.raise_for_status()

    return r.json()["result"]


def update_change(sys_id, notes, state=None):
    """
    Updates ONLY if change is active and not closed.
    Prevents 403 from closed records.
    """

    instance, user, password = _sn()

    # Validate change exists
    record = _get_change(sys_id)

    if not record:
        raise RuntimeError(f"Change {sys_id} not found.")

    if str(record.get("active")).lower() == "false":
        raise RuntimeError(
            f"Refusing to update closed change: {record.get('number')}"
        )

    payload = {"work_notes": notes}

    if state:
        payload["state"] = state

    r = requests.patch(
        f"https://{instance}/api/now/table/change_request/{sys_id}",
        auth=(user, password),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        json=payload,
        timeout=20,
    )

    if r.status_code == 403:
        raise RuntimeError(
            f"403 Forbidden while updating {record.get('number')}. "
            f"Check ACL or state restrictions."
        )

    r.raise_for_status()

    return r.json()["result"]


def attach_file(sys_id, filename, data):
    """
    Attach JSON file to the SAME change record.
    """

    instance, user, password = _sn()

    r = requests.post(
        f"https://{instance}/api/now/attachment/file"
        f"?table_name=change_request&table_sys_id={sys_id}&file_name={filename}",
        auth=(user, password),
        headers={"Content-Type": "application/octet-stream", "Accept": "application/json"},
        data=json.dumps(data, indent=2).encode(),
        timeout=20,
    )

    r.raise_for_status()

    return True



# ── Step functions ────────────────────────────────────────────────────────────

def run_pre_health_check(change_number):
    run_id = trigger_workflow("pre_health_check.yml", {"change_number": change_number})
    run    = wait_for_workflow(run_id)
    if run["conclusion"] == "failure":
        raise RuntimeError(f"pre_health_check FAILED → {run.get('html_url')}")
    health = download_artifact(run_id, "pre_health")
    return health, {"run_id": run_id, "url": run.get("html_url"), "elapsed": run.get("elapsed_seconds")}


def run_apply_change(scenario_label, change_number):
    scenario_map = {
        "Small Disk (PASS)":      "small_disk",
        "Large Disk Fill (FAIL)": "large_disk",
        "CPU Stress (FAIL)":      "cpu_stress",
        "Stop a Service (FAIL)":  "stop_service",
    }
    scenario = scenario_map.get(scenario_label, scenario_label)
    run_id   = trigger_workflow("apply_change.yml", {"scenario": scenario, "change_number": change_number})
    run      = wait_for_workflow(run_id, timeout_seconds=420)
    if run["conclusion"] == "failure":
        raise RuntimeError(f"apply_change FAILED → {run.get('html_url')}")
    info = download_artifact(run_id, "change_applied")
    return info, {"run_id": run_id, "url": run.get("html_url"), "elapsed": run.get("elapsed_seconds")}


def run_post_health_check(change_number):
    run_id = trigger_workflow("post_health_check.yml", {"change_number": change_number})
    run    = wait_for_workflow(run_id)
    if run["conclusion"] == "failure":
        raise RuntimeError(f"post_health_check FAILED → {run.get('html_url')}")
    health = download_artifact(run_id, "post_health")
    return health, {"run_id": run_id, "url": run.get("html_url"), "elapsed": run.get("elapsed_seconds")}


def run_cleanup(scenario_label):
    scenario_map = {
        "Small Disk (PASS)":      "small_disk",
        "Large Disk Fill (FAIL)": "large_disk",
        "CPU Stress (FAIL)":      "cpu_stress",
        "Stop a Service (FAIL)":  "stop_service",
    }
    scenario = scenario_map.get(scenario_label, "small_disk")
    run_id   = trigger_workflow("cleanup.yml", {"scenario": scenario})
    run      = wait_for_workflow(run_id, timeout_seconds=120)
    return {"run_id": run_id, "url": run.get("html_url"), "conclusion": run.get("conclusion")}


# ── Diff + Risk ───────────────────────────────────────────────────────────────

def compare(pre, post):

    def si(val, d=0):
        try:    return int(val)
        except: return d

    def sf(val, d=0.0):
        try:    return float(val)
        except: return d

    pre_root  = si(pre.get("disk",  {}).get("root", {}).get("used_percent", 0))
    post_root = si(post.get("disk", {}).get("root", {}).get("used_percent", 0))
    pre_tmp   = si(pre.get("disk",  {}).get("tmp",  {}).get("used_percent", 0))
    post_tmp  = si(post.get("disk", {}).get("tmp",  {}).get("used_percent", 0))
    pre_load  = sf(pre.get("load_1m",  0))
    post_load = sf(post.get("load_1m", 0))
    pre_mem   = si(pre.get("memory",  {}).get("used_percent", 0))
    post_mem  = si(post.get("memory", {}).get("used_percent", 0))

    pre_svcs  = pre.get("services",  {})
    post_svcs = post.get("services", {})
    svc_changes = {
        svc: {"before": pre_svcs.get(svc, "unknown"), "after": post_svcs.get(svc, "unknown")}
        for svc in set(pre_svcs) | set(post_svcs)
        if pre_svcs.get(svc) != post_svcs.get(svc)
    }

    return {
        "disk_root_before":   pre_root,
        "disk_root_after":    post_root,
        "disk_root_delta":    post_root - pre_root,
        "disk_tmp_before":    pre_tmp,
        "disk_tmp_after":     post_tmp,
        "disk_tmp_delta":     post_tmp - pre_tmp,
        "load_before":        pre_load,
        "load_after":         post_load,
        "load_delta":         round(post_load - pre_load, 2),
        "memory_before":      pre_mem,
        "memory_after":       post_mem,
        "memory_delta":       post_mem - pre_mem,
        "service_changes":    svc_changes,
        "top_processes_post": post.get("top_processes", ""),
        "pre_warnings":       pre.get("warnings", []),
    }


def risk_score(diff):
    score, reasons = 0, []

    if   diff["disk_root_after"] > 90: score += 50; reasons.append(f"Root disk critical: {diff['disk_root_after']}%")
    elif diff["disk_root_after"] > 80: score += 25; reasons.append(f"Root disk high: {diff['disk_root_after']}%")
    if   diff["disk_tmp_after"]  > 90: score += 35; reasons.append(f"/tmp critical: {diff['disk_tmp_after']}%")
    elif diff["disk_tmp_after"]  > 75: score += 15; reasons.append(f"/tmp elevated: {diff['disk_tmp_after']}%")
    if   diff["load_after"] > 8: score += 40; reasons.append(f"Load very high: {diff['load_after']}")
    elif diff["load_after"] > 3: score += 20; reasons.append(f"Load elevated: {diff['load_after']}")
    if   diff["disk_root_delta"] > 20: score += 20; reasons.append(f"Root disk grew +{diff['disk_root_delta']}%")
    elif diff["disk_root_delta"] > 10: score += 10; reasons.append(f"Root disk grew +{diff['disk_root_delta']}%")
    if   diff["disk_tmp_delta"]  > 15: score += 15; reasons.append(f"/tmp grew +{diff['disk_tmp_delta']}%")

    failed = [
        f"{s}: {v['before']}→{v['after']}"
        for s, v in diff["service_changes"].items()
        if v["after"] in ("inactive", "failed", "unknown")
    ]
    if failed:
        score += 30 * len(failed)
        reasons.append(f"Service failures: {', '.join(failed)}")

    score    = min(score, 100)
    severity = "Low" if score < 20 else "Medium" if score < 50 else "High" if score < 80 else "Critical"
    return {"score": score, "severity": severity, "reasons": reasons}


# ── AI Validation ─────────────────────────────────────────────────────────────

def ai_validate(pre, post, diff, risk, change):
    api_key = _secret("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY missing from Streamlit secrets.")

    client     = OpenAI(api_key=api_key)
    pre_clean  = {k: v for k, v in pre.items()  if not k.startswith("_")}
    post_clean = {k: v for k, v in post.items() if not k.startswith("_")}

    system = """You are a senior Site Reliability Engineer validating a Linux change.
Health data was collected by Ansible playbooks running via GitHub Actions.
You reason carefully from structured JSON, write clear ServiceNow work notes,
and always end with a definitive PASS or FAIL. You never hedge."""

    prompt = f"""A change has been applied to a managed Oracle Linux server.

## Pre-Change Health
```json
{json.dumps(pre_clean, indent=2)}
```

## Post-Change Health
```json
{json.dumps(post_clean, indent=2)}
```

## Diff
```json
{json.dumps(diff, indent=2)}
```

## Risk Model
```json
{json.dumps(risk, indent=2)}
```

## ServiceNow Change: {change.get('number', 'N/A')}

Respond with:

### 1. DISK ANALYSIS
### 2. LOAD & MEMORY
### 3. SERVICE ANALYSIS
### 4. RISK ASSESSMENT
### 5. SERVICENOW WORK NOTES
3-5 sentences, professional, past-tense.

### 6. FINAL VERDICT
`VALIDATION: PASS` or `VALIDATION: FAIL`

If FAIL — list exact remediation steps."""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        max_tokens=1500,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
    )

    text    = response.choices[0].message.content or ""
    verdict = "PASS" if "VALIDATION: PASS" in text.upper() else "FAIL"

    sn_notes = text
    if "### 5. SERVICENOW WORK NOTES" in text:
        try:
            sn_notes = text.split("### 5. SERVICENOW WORK NOTES")[1].split("### 6.")[0].strip()
        except Exception:
            sn_notes = text[:600]

    return {
        "verdict":       verdict,
        "full_analysis": text,
        "sn_notes":      sn_notes,
        "model":         response.model,
        "tokens":        (response.usage.prompt_tokens or 0) + (response.usage.completion_tokens or 0),
    }