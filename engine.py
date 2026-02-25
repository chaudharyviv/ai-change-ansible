from __future__ import annotations

"""
Enterprise Engine — AI Change Governance Platform
Production-grade version with:
- Safe GitHub workflow matching
- Structured LLM JSON validation
- Pre-check AI gating
- Balanced risk scoring
- Defensive parsing
- Strong error handling
"""

import io
import json
import os
import time
import zipfile
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional

import requests
from openai import OpenAI
import streamlit as st

# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ai-change-engine")


# ──────────────────────────────────────────────────────────────────────────────
# Secrets Helper
# ──────────────────────────────────────────────────────────────────────────────

def _secret(key: str) -> str:
    try:
        return st.secrets[key]
    except Exception:
        return os.getenv(key, "")


# ──────────────────────────────────────────────────────────────────────────────
# GitHub Configuration
# ──────────────────────────────────────────────────────────────────────────────

def _repo() -> str:
    owner = _secret("GITHUB_OWNER")
    repo  = _secret("GITHUB_REPO")
    if not owner or not repo:
        raise RuntimeError("GitHub owner/repo not configured.")
    return f"{owner}/{repo}"


def _gh_headers() -> Dict[str, str]:
    token = _secret("GITHUB_PAT")
    if not token:
        raise RuntimeError("GITHUB_PAT missing.")
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

def _get_workflow_id(workflow_filename: str) -> str:
    """
    Dynamically get workflow ID from filename.
    This replaces the hardcoded _WORKFLOW_IDS dictionary.
    """
    repo = _repo()
    headers = _gh_headers()
    
    logger.info(f"Looking up workflow ID for: {workflow_filename}")
    
    r = requests.get(
        f"https://api.github.com/repos/{repo}/actions/workflows",
        headers=headers,
        timeout=15,
    )
    r.raise_for_status()
    
    for workflow in r.json().get("workflows", []):
        # Match by filename (e.g., "pre_health_check.yml")
        if workflow["path"].endswith(workflow_filename):
            workflow_id = str(workflow["id"])
            logger.info(f"Found workflow ID {workflow_id} for {workflow_filename}")
            return workflow_id
    
    raise RuntimeError(
        f"Workflow '{workflow_filename}' not found in repository. "
        f"Available workflows: {[w['name'] for w in r.json().get('workflows', [])]}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# GitHub Workflow Management (Safe Matching)
# ──────────────────────────────────────────────────────────────────────────────

def trigger_workflow(workflow_filename: str, inputs: Dict[str, str]) -> str:
    repo = _repo()
    headers = _gh_headers()
    
    # Get workflow ID dynamically
    workflow_id = _get_workflow_id(workflow_filename)
    
    created_after = datetime.now(timezone.utc).isoformat()
    
    logger.info(f"Triggering workflow {workflow_filename} (ID: {workflow_id})")
    
    r = requests.post(
        f"https://api.github.com/repos/{repo}/actions/workflows/{workflow_id}/dispatches",
        headers=headers,
        json={"ref": "main", "inputs": inputs},
        timeout=20,
    )
    if r.status_code != 204:
        raise RuntimeError(f"Workflow dispatch failed: {r.text}")
    
    return _find_run_id(workflow_id, created_after)


def _find_run_id(workflow_id: str, created_after: str) -> str:
    repo = _repo()
    headers = _gh_headers()
    
    logger.info(f"Waiting for workflow run to appear (created after {created_after})")
    
    for attempt in range(20):
        r = requests.get(
            f"https://api.github.com/repos/{repo}/actions/workflows/{workflow_id}/runs",
            headers=headers,
            params={"per_page": 10},
            timeout=15,
        )
        r.raise_for_status()
        runs = r.json().get("workflow_runs", [])
        
        for run in runs:
            if run["created_at"] >= created_after:
                run_id = str(run["id"])
                logger.info(f"Found workflow run: {run_id}")
                return run_id
        
        logger.debug(f"Attempt {attempt + 1}/20: No matching run yet, waiting...")
        time.sleep(3)
    
    raise RuntimeError("Matching workflow run not found after 60 seconds.")

def wait_for_workflow(run_id: str, timeout_seconds: int = 600) -> Dict[str, Any]:
    repo = _repo()
    headers = _gh_headers()
    start = time.time()

    while True:
        elapsed = time.time() - start
        if elapsed > timeout_seconds:
            raise RuntimeError("Workflow timeout exceeded.")

        r = requests.get(
            f"https://api.github.com/repos/{repo}/actions/runs/{run_id}",
            headers=headers,
            timeout=15,
        )
        r.raise_for_status()
        run = r.json()

        if run["status"] == "completed":
            run["elapsed_seconds"] = int(elapsed)
            return run

        time.sleep(8)


def download_artifact(run_id: str, artifact_name: str) -> Dict[str, Any]:
    repo = _repo()
    headers = _gh_headers()

    r = requests.get(
        f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/artifacts",
        headers=headers,
        timeout=20,
    )
    r.raise_for_status()

    artifacts = r.json().get("artifacts", [])
    target = next((a for a in artifacts if a["name"] == artifact_name), None)

    if not target:
        raise RuntimeError(f"Artifact '{artifact_name}' not found.")

    dl = requests.get(target["archive_download_url"], headers=headers, timeout=30)
    dl.raise_for_status()

    with zipfile.ZipFile(io.BytesIO(dl.content)) as zf:
        json_files = [n for n in zf.namelist() if n.endswith(".json")]
        if not json_files:
            raise RuntimeError("No JSON file found in artifact.")
        with zf.open(json_files[0]) as jf:
            return json.loads(jf.read().decode())


# ──────────────────────────────────────────────────────────────────────────────
# ServiceNow Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _sn() -> Tuple[str, str, str]:
    instance = _secret("SERVICENOW_INSTANCE")
    user     = _secret("SERVICENOW_USER")
    password = _secret("SERVICENOW_PASS")
    if not all([instance, user, password]):
        raise RuntimeError("ServiceNow secrets missing.")
    return instance, user, password


def create_change() -> Dict[str, Any]:
    instance, user, password = _sn()
    r = requests.post(
        f"https://{instance}/api/now/table/change_request",
        auth=(user, password),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        json={
            "short_description": "AI-Governed Linux Change (Ansible + GitHub Actions)",
            "description":       "Automated pre/post Ansible health validation via OPENAI AI.",
            "type":              "normal",
            "state":             "-1",
        },
        timeout=20,
    )
    r.raise_for_status()
    result = r.json()["result"]
    return {"number": result["number"], "sys_id": result["sys_id"]}


def update_change(sys_id: str, notes: str, state: Optional[str] = None) -> None:
    instance, user, password = _sn()
    payload: Dict[str, Any] = {"work_notes": notes}
    if state is not None:
        payload["state"] = state
    requests.patch(
        f"https://{instance}/api/now/table/change_request/{sys_id}",
        auth=(user, password),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        json=payload,
        timeout=20,
    ).raise_for_status()


def attach_file(sys_id: str, filename: str, data: Dict[str, Any]) -> None:
    instance, user, password = _sn()
    requests.post(
        f"https://{instance}/api/now/attachment/file"
        f"?table_name=change_request&table_sys_id={sys_id}&file_name={filename}",
        auth=(user, password),
        headers={"Content-Type": "application/octet-stream", "Accept": "application/json"},
        data=json.dumps(data, indent=2).encode(),
        timeout=20,
    ).raise_for_status()


# ──────────────────────────────────────────────────────────────────────────────
# High-Level Workflow Step Helpers
# ──────────────────────────────────────────────────────────────────────────────

def run_pre_health_check(change_number: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    run_id = trigger_workflow("pre_health_check.yml", {"change_number": change_number})
    run    = wait_for_workflow(run_id)

    if run.get("conclusion") == "failure":
        raise RuntimeError(f"pre_health_check workflow FAILED. View: {run.get('html_url')}")

    health = download_artifact(run_id, "pre_health")
    return health, {
        "run_id":  run_id,
        "url":     run.get("html_url"),
        "elapsed": run.get("elapsed_seconds"),
    }


def run_apply_change(scenario_label: str, change_number: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    scenario_map = {
        "Small Disk (PASS)":      "small_disk",
        "Large Disk Fill (FAIL)": "large_disk",
        "CPU Stress (FAIL)":      "cpu_stress",
        "Stop a Service (FAIL)":  "stop_service",
    }
    scenario = scenario_map.get(scenario_label, scenario_label)

    run_id = trigger_workflow(
        "apply_change.yml",
        {"scenario": scenario, "change_number": change_number},
    )
    run = wait_for_workflow(run_id, timeout_seconds=420)

    if run.get("conclusion") == "failure":
        raise RuntimeError(f"apply_change workflow FAILED. View: {run.get('html_url')}")

    change_info = download_artifact(run_id, "change_applied")
    return change_info, {
        "run_id":  run_id,
        "url":     run.get("html_url"),
        "elapsed": run.get("elapsed_seconds"),
    }


def run_post_health_check(change_number: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    run_id = trigger_workflow("post_health_check.yml", {"change_number": change_number})
    run    = wait_for_workflow(run_id)

    if run.get("conclusion") == "failure":
        raise RuntimeError(f"post_health_check workflow FAILED. View: {run.get('html_url')}")

    health = download_artifact(run_id, "post_health")
    return health, {
        "run_id":  run_id,
        "url":     run.get("html_url"),
        "elapsed": run.get("elapsed_seconds"),
    }


def run_cleanup(scenario_label: str) -> Dict[str, Any]:
    scenario_map = {
        "Small Disk (PASS)":      "small_disk",
        "Large Disk Fill (FAIL)": "large_disk",
        "CPU Stress (FAIL)":      "cpu_stress",
        "Stop a Service (FAIL)":  "stop_service",
    }
    scenario = scenario_map.get(scenario_label, "small_disk")

    run_id = trigger_workflow("cleanup.yml", {"scenario": scenario})
    run    = wait_for_workflow(run_id, timeout_seconds=180)
    return {
        "run_id":     run_id,
        "url":        run.get("html_url"),
        "conclusion": run.get("conclusion"),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Diff Computation + Risk Engine
# ──────────────────────────────────────────────────────────────────────────────

def compare(pre: Dict[str, Any], post: Dict[str, Any]) -> Dict[str, Any]:

    def si(val: Any, default: int = 0) -> int:
        try:
            return int(val)
        except Exception:
            return default

    def sf(val: Any, default: float = 0.0) -> float:
        try:
            return float(val)
        except Exception:
            return default

    pre_root  = si(pre.get("disk",  {}).get("root", {}).get("used_percent", 0))
    post_root = si(post.get("disk", {}).get("root", {}).get("used_percent", 0))
    pre_tmp   = si(pre.get("disk",  {}).get("tmp",  {}).get("used_percent", 0))
    post_tmp  = si(post.get("disk", {}).get("tmp",  {}).get("used_percent", 0))

    pre_load  = sf(pre.get("load_1m",  0))
    post_load = sf(post.get("load_1m", 0))
    pre_mem   = si(pre.get("memory",  {}).get("used_percent", 0))
    post_mem  = si(post.get("memory", {}).get("used_percent", 0))

    pre_svcs  = pre.get("services",  {}) or {}
    post_svcs = post.get("services", {}) or {}
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


def risk_score(diff: Dict[str, Any]) -> Dict[str, Any]:
    absolute = 0
    delta = 0
    reasons = []

    # Absolute
    if diff["disk_root_after"] > 85:
        absolute += 40
        reasons.append("Root disk critically high.")
    if diff["load_after"] > 5:
        absolute += 30
        reasons.append("Load average elevated.")
    if diff["memory_after"] > 90:
        absolute += 25
        reasons.append("Memory usage critical.")

    # Delta
    if diff["disk_root_delta"] > 15:
        delta += 20
        reasons.append("Root disk growth significant.")
    if diff["load_delta"] > 3:
        delta += 20
        reasons.append("Load spike detected.")

    score = int((absolute * 0.7) + (delta * 0.3))
    score = min(score, 100)

    if score < 20:
        severity = "Low"
    elif score < 50:
        severity = "Medium"
    elif score < 80:
        severity = "High"
    else:
        severity = "Critical"

    return {"score": score, "severity": severity, "reasons": reasons}


# ──────────────────────────────────────────────────────────────────────────────
# AI Pre-Check Gate
# ──────────────────────────────────────────────────────────────────────────────

def ai_precheck_assessment(pre: Dict[str, Any]) -> Dict[str, Any]:
    if pre["disk"]["root"]["used_percent"] > 85:
        return {
            "proceed": False,
            "reason": "Root disk already above 85%.",
            "recommendation": "Cleanup disk before proceeding."
        }

    return {"proceed": True, "reason": "System healthy."}


# ──────────────────────────────────────────────────────────────────────────────
# Structured AI Validation
# ──────────────────────────────────────────────────────────────────────────────

def ai_validate(pre, post, diff, risk, change):
    api_key = _secret("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY missing.")

    client = OpenAI(api_key=api_key)

    prompt = f"""
Evaluate Linux change health.

PRE:
{json.dumps(pre)}

POST:
{json.dumps(post)}

DIFF:
{json.dumps(diff)}

RISK:
{json.dumps(risk)}

Return JSON:
{{
 "servicenow_notes": "...",
 "verdict": "PASS" or "FAIL",
 "remediation": "If FAIL"
}}
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        response_format={"type": "json_object"},
        messages=[{"role": "user", "content": prompt}],
    )

    result = json.loads(response.choices[0].message.content)

    return {
        "verdict": result["verdict"],
        "sn_notes": result["servicenow_notes"],
        "full_analysis": json.dumps(result, indent=2),
        "model": response.model,
        "tokens": response.usage.total_tokens,
    }