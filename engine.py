"""
engine.py — AI Change Governance Platform (GitHub Actions Edition)
==================================================================
Flow per step:
  1. Streamlit calls trigger_workflow(workflow, inputs)
     → POST to GitHub API → dispatches Actions run
  2. Streamlit calls wait_for_workflow(run_id)
     → polls GET /runs until completed / failed
  3. Streamlit calls download_artifact(run_id, name)
     → downloads ZIP artifact → extracts JSON
  4. OPENAI AI validates pre+post JSON
  5. ServiceNow updated with verdict + AI work notes

Streamlit Secrets required:
  OPENAI_API_KEY
  GITHUB_PAT          Personal Access Token (repo + actions:write + actions:read)
  GITHUB_OWNER        your GitHub username or org
  GITHUB_REPO         repository name
  SERVICENOW_INSTANCE e.g. dev12345.service-now.com
  SERVICENOW_USER
  SERVICENOW_PASS

GitHub Repository Secrets (set in repo Settings → Secrets → Actions):
  ORACLE_VM_HOST           Oracle VM public IP
  ORACLE_VM_USER           e.g. opc
  ORACLE_SSH_PRIVATE_KEY   Full PEM contents
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


# ── Secrets helper ────────────────────────────────────────────────────────────

# ── Secrets helper ────────────────────────────────────────────────────────────

def _secret(key: str) -> str:
    try:
        return st.secrets[key]
    except Exception:
        return os.getenv(key, "")


# ── Workflow IDs ──────────────────────────────────────────────────────────────
# Using numeric IDs avoids 404s from filename-based dispatch on some PAT configs.
# Get yours from: https://api.github.com/repos/OWNER/REPO/actions/workflows

_WORKFLOW_IDS = {
    "pre_health_check.yml":  "237876997",
    "apply_change.yml":      "237876994",
    "post_health_check.yml": "237876996",
    "cleanup.yml":           "237876995",
}


# ── GitHub API helpers ────────────────────────────────────────────────────────

def _gh_headers() -> dict:
    token = _secret("GITHUB_PAT")
    if not token:
        raise RuntimeError("GITHUB_PAT missing from Streamlit secrets.")
    return {
        "Authorization":        f"Bearer {token}",
        "Accept":               "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

def _repo() -> str:
    owner = _secret("GITHUB_OWNER")
    repo  = _secret("GITHUB_REPO")
    if not owner or not repo:
        raise RuntimeError("GITHUB_OWNER and GITHUB_REPO must be set in Streamlit secrets.")
    return f"{owner}/{repo}"


# ══════════════════════════════════════════════════════════════════════════════
# GITHUB ACTIONS — trigger, poll, download
# ══════════════════════════════════════════════════════════════════════════════

def trigger_workflow(workflow_filename: str, inputs: dict) -> str:
    """
    Dispatch a workflow_dispatch event to GitHub Actions.
    Uses numeric workflow ID to avoid 404s from filename-based dispatch.
    Returns the run_id of the triggered run.
    """
    repo        = _repo()
    headers     = _gh_headers()
    workflow_id = _WORKFLOW_IDS.get(workflow_filename, workflow_filename)

    # Record time just before dispatch so we can find this specific run
    before_ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    r = requests.post(
        f"https://api.github.com/repos/{repo}/actions/workflows/{workflow_id}/dispatches",
        headers=headers,
        json={"ref": "main", "inputs": inputs},
        timeout=15,
    )
    if r.status_code != 204:
        raise RuntimeError(
            f"GitHub dispatch failed ({r.status_code}): {r.text}"
        )

    # Give GitHub 3s to register the run, then find its run_id
    time.sleep(3)
    return _find_run_id(workflow_filename, before_ts)
def _find_run_id(workflow_filename: str, created_after: str) -> str:
    """
    Find the run_id of the most recently triggered run for a workflow.
    Retries for up to 30 seconds in case GitHub is slow to register it.
    Uses numeric workflow ID for consistency.
    """
    repo        = _repo()
    headers     = _gh_headers()
    workflow_id = _WORKFLOW_IDS.get(workflow_filename, workflow_filename)

    for _ in range(10):
        r = requests.get(
            f"https://api.github.com/repos/{repo}/actions/workflows/{workflow_id}/runs",
            headers=headers,
            params={"per_page": 5, "created": f">={created_after}"},
            timeout=15,
        )
        r.raise_for_status()
        runs = r.json().get("workflow_runs", [])
        if runs:
            return str(runs[0]["id"])
        time.sleep(3)

    raise RuntimeError(
        f"Could not find a new run for {workflow_filename} after dispatch. "
        "Check GitHub Actions tab in your repo."
    )


def wait_for_workflow(run_id: str, timeout_seconds: int = 600) -> dict:
    """
    Poll GitHub Actions until the run completes or timeout is reached.
    Shows a Streamlit progress bar while waiting.
    Returns the full run object with status and conclusion.
    """
    repo     = _repo()
    headers  = _gh_headers()
    start    = time.time()
    progress = st.progress(0, text="GitHub Actions running...")
    elapsed  = 0

    while elapsed < timeout_seconds:
        r = requests.get(
            f"https://api.github.com/repos/{repo}/actions/runs/{run_id}",
            headers=headers,
            timeout=15,
        )
        r.raise_for_status()
        run        = r.json()
        status     = run.get("status")
        conclusion = run.get("conclusion")
        elapsed    = round(time.time() - start)
        pct        = min(int(elapsed / timeout_seconds * 100), 95)

        progress.progress(
            pct,
            text=f"GitHub Actions: {status} ({elapsed}s) — "
                 f"[View run]({run.get('html_url', '')})"
        )

        if status == "completed":
            progress.progress(100, text=f"Completed: {conclusion}")
            if conclusion not in ("success", "failure"):
                raise RuntimeError(
                    f"Workflow run {run_id} ended with unexpected conclusion: {conclusion}"
                )
            run["elapsed_seconds"] = elapsed
            return run

        time.sleep(8)

    raise RuntimeError(
        f"Workflow run {run_id} did not complete within {timeout_seconds}s."
    )


def download_artifact(run_id: str, artifact_name: str) -> dict:
    """
    Download a named artifact from a completed GitHub Actions run.
    Artifacts are ZIP files — extracts the JSON inside and parses it.
    """
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
        available = [a["name"] for a in artifacts]
        raise RuntimeError(
            f"Artifact '{artifact_name}' not found in run {run_id}. "
            f"Available: {available}"
        )

    dl = requests.get(
        target["archive_download_url"],
        headers=headers,
        timeout=30,
    )
    dl.raise_for_status()

    with zipfile.ZipFile(io.BytesIO(dl.content)) as zf:
        json_files = [n for n in zf.namelist() if n.endswith(".json")]
        if not json_files:
            raise RuntimeError(f"No JSON file found inside artifact '{artifact_name}'.")
        with zf.open(json_files[0]) as jf:
            return json.loads(jf.read().decode())


# ══════════════════════════════════════════════════════════════════════════════
# SERVICENOW
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
            "short_description":  "AI-Governed Linux Change (Ansible + GitHub Actions)",
            "description":        "Automated pre/post Ansible health validation via Claude AI.",
            "type":               "normal",
            "state":              "-1",
            "assigned_to":        "admin",
            "planned_start_date": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "planned_end_date":   datetime.utcnow().strftime("%Y-%m-%d ") + "23:59:59",
        },
        timeout=15,
    )
    r.raise_for_status()
    result = r.json()["result"]
    return {"number": result["number"], "sys_id": result["sys_id"]}


def update_change(sys_id: str, notes: str, state=None) -> None:
    instance, user, password = _sn()
    payload = {"work_notes": notes}
    if state:
        payload["state"] = state
    requests.patch(
        f"https://{instance}/api/now/table/change_request/{sys_id}",
        auth=(user, password),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        json=payload,
        timeout=15,
    ).raise_for_status()


def attach_file(sys_id: str, filename: str, data: dict) -> None:
    instance, user, password = _sn()
    requests.post(
        f"https://{instance}/api/now/attachment/file"
        f"?table_name=change_request&table_sys_id={sys_id}&file_name={filename}",
        auth=(user, password),
        headers={"Content-Type": "application/octet-stream", "Accept": "application/json"},
        data=json.dumps(data, indent=2).encode(),
        timeout=15,
    ).raise_for_status()


# ══════════════════════════════════════════════════════════════════════════════
# HIGH-LEVEL STEP FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════════════
# HIGH-LEVEL STEP FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def run_pre_health_check(change_number: str):
    """Trigger pre_health_check → wait → download artifact. Returns (health, run_info)."""
    run_id = trigger_workflow("pre_health_check.yml", {"change_number": change_number})
    run    = wait_for_workflow(run_id)

    if run["conclusion"] == "failure":
        raise RuntimeError(f"pre_health_check FAILED. View: {run.get('html_url')}")

    health = download_artifact(run_id, "pre_health")
    return health, {"run_id": run_id, "url": run.get("html_url"), "elapsed": run.get("elapsed_seconds")}


def run_apply_change(scenario_label: str, change_number: str):
    """Trigger apply_change → wait → download artifact. Returns (change_info, run_info)."""
    scenario_map = {
        "Small Disk (PASS)":      "small_disk",
        "Large Disk Fill (FAIL)": "large_disk",
        "CPU Stress (FAIL)":      "cpu_stress",
        "Stop a Service (FAIL)":  "stop_service",
    }
    scenario = scenario_map.get(scenario_label, scenario_label)

    run_id = trigger_workflow("apply_change.yml", {
        "scenario":      scenario,
        "change_number": change_number,
    })
    run = wait_for_workflow(run_id, timeout_seconds=420)

    if run["conclusion"] == "failure":
        raise RuntimeError(f"apply_change FAILED. View: {run.get('html_url')}")

    change_info = download_artifact(run_id, "change_applied")
    return change_info, {"run_id": run_id, "url": run.get("html_url"), "elapsed": run.get("elapsed_seconds")}


def run_post_health_check(change_number: str):
    """Trigger post_health_check → wait → download artifact. Returns (health, run_info)."""
    run_id = trigger_workflow("post_health_check.yml", {"change_number": change_number})
    run    = wait_for_workflow(run_id)

    if run["conclusion"] == "failure":
        raise RuntimeError(f"post_health_check FAILED. View: {run.get('html_url')}")

    health = download_artifact(run_id, "post_health")
    return health, {"run_id": run_id, "url": run.get("html_url"), "elapsed": run.get("elapsed_seconds")}


def run_cleanup(scenario_label: str) -> dict:
    """Trigger cleanup workflow."""
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


# ══════════════════════════════════════════════════════════════════════════════
# DIFF + RISK
# ══════════════════════════════════════════════════════════════════════════════

def compare(pre: dict, post: dict) -> dict:

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


def risk_score(diff: dict) -> dict:
    score, reasons = 0, []

    if   diff["disk_root_after"] > 90: score += 50; reasons.append(f"Root disk critical: {diff['disk_root_after']}%")
    elif diff["disk_root_after"] > 80: score += 25; reasons.append(f"Root disk high: {diff['disk_root_after']}%")

    if   diff["disk_tmp_after"]  > 90: score += 35; reasons.append(f"/tmp critical: {diff['disk_tmp_after']}%")
    elif diff["disk_tmp_after"]  > 75: score += 15; reasons.append(f"/tmp elevated: {diff['disk_tmp_after']}%")

    if   diff["load_after"] > 8: score += 40; reasons.append(f"Load very high: {diff['load_after']}")
    elif diff["load_after"] > 3: score += 20; reasons.append(f"Load elevated: {diff['load_after']}")

    if   diff["disk_root_delta"] > 20: score += 20; reasons.append(f"Root disk grew +{diff['disk_root_delta']}%")
    elif diff["disk_root_delta"] > 10: score += 10; reasons.append(f"Root disk grew +{diff['disk_root_delta']}%")

    if diff["disk_tmp_delta"] > 15: score += 15; reasons.append(f"/tmp grew +{diff['disk_tmp_delta']}%")

    failed = [
        f"{s}: {v['before']}→{v['after']}"
        for s, v in diff["service_changes"].items()
        if v["after"] in ("inactive", "failed", "unknown")
    ]
    if failed:
        score += 30 * len(failed)
        reasons.append(f"Service failures: {', '.join(failed)}")

    score    = min(score, 100)
    severity = (
        "Low"      if score < 20 else
        "Medium"   if score < 50 else
        "High"     if score < 80 else
        "Critical"
    )
    return {"score": score, "severity": severity, "reasons": reasons}

# ══════════════════════════════════════════════════════════════════════════════
# AI VALIDATION
# ══════════════════════════════════════════════════════════════════════════════

def ai_validate(pre: dict, post: dict, diff: dict, risk: dict, change: dict) -> dict:
    """
    Send Ansible health JSON + diff + risk to OPENAI.
    OPENAI produces PASS/FAIL verdict + ServiceNow work notes.
    """
    api_key = _secret("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY missing.")

    client = OpenAI(api_key=api_key)

    # Strip internal keys before sending to AI
    pre_clean  = {k: v for k, v in pre.items()  if not k.startswith("_")}
    post_clean = {k: v for k, v in post.items() if not k.startswith("_")}

    system = """You are a senior Site Reliability Engineer validating a Linux change.
Health data was collected by Ansible playbooks running via GitHub Actions.
You reason carefully from structured JSON, write clear ServiceNow work notes,
and always end with a definitive PASS or FAIL. You never hedge."""

    prompt = f"""A change has been applied to a managed Oracle Linux server.
Below is the structured output from Ansible health-check playbooks.

## Pre-Change Health (Ansible JSON)
```json
{json.dumps(pre_clean, indent=2)}
```

## Post-Change Health (Ansible JSON)
```json
{json.dumps(post_clean, indent=2)}
```

## Python Diff
```json
{json.dumps(diff, indent=2)}
```

## Risk Model
```json
{json.dumps(risk, indent=2)}
```

## ServiceNow Change: {change.get('number', 'N/A')}

---

Respond with these sections:

### 1. DISK ANALYSIS
Root and /tmp: are levels safe? Is the delta expected for this change type?

### 2. LOAD & MEMORY
Load average and memory: acceptable post-change?

### 3. SERVICE ANALYSIS
Any services that changed state? Are failures acceptable or critical?

### 4. RISK ASSESSMENT
Agree or disagree with the risk score of {risk['score']}/100 ({risk['severity']})?

### 5. SERVICENOW WORK NOTES
3-5 sentences, professional, past-tense, ready to paste into ServiceNow.

### 6. FINAL VERDICT
End with exactly one of:
`VALIDATION: PASS`
`VALIDATION: FAIL`

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
