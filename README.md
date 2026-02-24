# AI Change Governance — GitHub Actions Edition
## Setup Guide

---

## Architecture

```
Streamlit Community Cloud
        │  GitHub REST API  (PAT token)
        │  POST /actions/workflows/{id}/dispatches
        ▼
GitHub Actions Runner  (ubuntu-latest, 7GB RAM, FREE)
        │  pip install ansible
        │  ansible-playbook + SSH
        ▼
Oracle Cloud VM  (1GB AMD micro, Always Free)
        │  Managed node only — no Ansible installed
        │  Runs: df, free, ps, dd, yes, systemctl
        │  Writes: /tmp/pre_health.json
        │           /tmp/change_applied.json
        │           /tmp/post_health.json
        ▼
GitHub Actions uploads JSON as artifact
        │
        ▼
Streamlit downloads artifact via GitHub API
        │
        ▼
OPENAI AI validates → ServiceNow updated
```

---

## Repository Structure

```
your-repo/
├── app.py
├── engine.py
├── requirements.txt
├── playbooks/
│   ├── pre_health_check.yml
│   ├── apply_change.yml
│   └── post_health_check.yml
└── .github/
    └── workflows/
        ├── pre_health_check.yml
        ├── apply_change.yml
        ├── post_health_check.yml
        └── cleanup.yml
```

---

## Part 1 — Oracle Cloud VM (1GB AMD Micro)

```bash
# This VM is the MANAGED NODE only — nothing to install
# Just ensure SSH is open (port 22) and python3 is present

# In Oracle Cloud Console → VCN → Security Lists → Ingress:
# TCP port 22, Source: 0.0.0.0/0

# Verify python3 available (default on Oracle Linux 9)
python3 --version
```

---

## Part 2 — GitHub Repository Setup

### 2a. Create a GitHub repo and push all files

### 2b. Add GitHub Repository Secrets
Go to: **repo → Settings → Secrets and variables → Actions → New repository secret**

| Secret Name | Value |
|-------------|-------|
| `ORACLE_VM_HOST` | Oracle VM public IP e.g. `140.238.x.x` |
| `ORACLE_VM_USER` | `opc` |
| `ORACLE_SSH_PRIVATE_KEY` | Full contents of your `.pem` private key |

### 2c. Enable GitHub Actions
Go to: **repo → Actions → Enable Actions**

### 2d. Test manually first
Go to: **repo → Actions → pre_health_check → Run workflow**
- Enter a change number: `CHG0000001`
- Click Run workflow
- Watch it succeed and produce an artifact

---

## Part 3 — Streamlit Secrets

### Streamlit Cloud
App Settings → Secrets → paste:

```toml
OPENAI_API_KEY      = "sk-..."
GITHUB_PAT          = "github_pat_..."
GITHUB_OWNER        = "your-username"
GITHUB_REPO         = "your-repo-name"
SERVICENOW_INSTANCE = "dev12345.service-now.com"
SERVICENOW_USER     = "admin"
SERVICENOW_PASS     = "password"
```

### GitHub PAT scopes needed
Create at: github.com → Settings → Developer settings → Personal access tokens → Fine-grained tokens

**Repository permissions:**
- Actions: Read and Write
- Contents: Read
- Metadata: Read

---

## Part 4 — GitHub Actions Timing

| Workflow | Typical duration |
|----------|-----------------|
| pre_health_check | ~90s (60s ansible install + 30s playbook) |
| apply_change (small_disk) | ~90s |
| apply_change (large_disk) | ~4-5 min (2GB write) |
| apply_change (cpu_stress) | ~90s |
| post_health_check | ~90s |
| cleanup | ~30s |

The Streamlit UI shows a live progress bar during each wait.

---

## Part 5 — Demo Walkthrough

| Step | Button | GitHub Actions | Oracle VM |
|------|--------|---------------|-----------|
| 1 | Create Change | — | — |
| 2 | Pre-Check | `pre_health_check.yml` runs | df, free, ps captured |
| 3 | Execute Change | `apply_change.yml -e scenario=X` runs | dd / yes / systemctl |
| 4 | Post-Check + AI | `post_health_check.yml` runs | df, free, ps captured |
| — | Cleanup | `cleanup.yml` runs | files removed, services restored |

### Showing the demo
During each step, click the **[View Actions run]** link in the Streamlit UI —
this takes you directly to the GitHub Actions log where the audience can see
Ansible running tasks in real time. This is the most impressive part.

---

## Scenario Expected Outcomes

| Scenario | /tmp delta | Load delta | Services | AI Verdict |
|----------|-----------|-----------|----------|------------|
| Small Disk | +~1% | 0 | all active | ✅ PASS |
| Large Disk | +50-80% | 0 | all active | ❌ FAIL |
| CPU Stress | 0 | +4-8 | all active | ❌ FAIL |
| Stop Service | 0 | 0 | chronyd ❌ | ❌ FAIL |
