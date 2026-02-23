# AI Change Governance Platform — Ansible Edition
## Setup Guide: Oracle Cloud → Ansible → OPENAI → ServiceNow

---

## Architecture

```
┌─────────────────────────┐
│   Streamlit Cloud       │
│   app.py + engine.py    │
└────────────┬────────────┘
             │ SSH (paramiko)
             ▼
┌─────────────────────────────────────────┐
│  Control Node — Oracle VM #1 (opc)      │
│                                         │
│  ~/ansible_project/                     │
│    playbooks/                           │
│      inventory.ini                      │
│      pre_health_check.yml               │
│      apply_change.yml                   │
│      post_health_check.yml              │
│                                         │
│  ansible-playbook ──────────────────┐  │
└─────────────────────────────────────│──┘
                                      │ SSH (ansible)
                                      ▼
                       ┌──────────────────────────────┐
                       │  Managed Node — Oracle VM #2  │
                       │                               │
                       │  /tmp/pre_health.json         │
                       │  /tmp/change_applied.json     │
                       │  /tmp/post_health.json        │
                       └──────────────────────────────┘
```

---

## Part 1 — Oracle Cloud Setup

### VM #1: Control Node
**Shape:** VM.Standard.A1.Flex — 1 OCPU, 6GB RAM — Always Free
**OS:** Oracle Linux 9

```bash
# SSH in as opc, then:
sudo dnf install -y ansible python3-pip
pip3 install --user ansible

# Create project structure
mkdir -p ~/ansible_project/playbooks
```

### VM #2: Managed Node
**Shape:** VM.Standard.A1.Flex — 1 OCPU, 6GB RAM — Always Free
**OS:** Oracle Linux 9

```bash
# No software install needed — just needs SSH access from Control Node
# Ensure python3 is available (default on OL9)
python3 --version
```

---

## Part 2 — Control Node Setup

### 2a. Copy SSH key for Managed Node access
```bash
# On Control Node — generate a key pair for ansible to use
ssh-keygen -t rsa -b 2048 -f ~/.ssh/managed_node -N ""

# Copy public key to Managed Node
ssh-copy-id -i ~/.ssh/managed_node.pub opc@MANAGED_NODE_IP

# Test it works
ssh -i ~/.ssh/managed_node opc@MANAGED_NODE_IP hostname
```

### 2b. Upload playbooks to Control Node
```bash
# From your local machine:
scp playbooks/inventory.ini         opc@CONTROL_NODE_IP:~/ansible_project/playbooks/
scp playbooks/pre_health_check.yml  opc@CONTROL_NODE_IP:~/ansible_project/playbooks/
scp playbooks/apply_change.yml      opc@CONTROL_NODE_IP:~/ansible_project/playbooks/
scp playbooks/post_health_check.yml opc@CONTROL_NODE_IP:~/ansible_project/playbooks/
```

### 2c. Edit inventory.ini on Control Node
```bash
# On Control Node:
nano ~/ansible_project/playbooks/inventory.ini

# Replace MANAGED_NODE_IP with the actual private IP of VM #2
# Example:
[managed]
managed-node ansible_host=10.0.0.5 ansible_user=opc ansible_ssh_private_key_file=~/.ssh/managed_node ansible_ssh_common_args='-o StrictHostKeyChecking=no'
```

### 2d. Test Ansible connectivity
```bash
# On Control Node:
cd ~/ansible_project
ansible managed -i playbooks/inventory.ini -m ping
# Expected: managed-node | SUCCESS => { "ping": "pong" }
```

### 2e. Test pre-health playbook manually
```bash
# On Control Node:
ansible-playbook playbooks/pre_health_check.yml -i playbooks/inventory.ini
cat /tmp/pre_health.json | python3 -m json.tool | head -30
```

---

## Part 3 — Streamlit Community Cloud

### 3a. Push to GitHub
```
your-repo/
  app.py
  engine.py
  requirements.txt
  playbooks/
    pre_health_check.yml
    apply_change.yml
    post_health_check.yml
    inventory.ini
  .gitignore
```

**.gitignore must include:**
```
.streamlit/secrets.toml
*.pem
*.key
```

### 3b. Deploy on Streamlit Cloud
1. Go to [share.streamlit.io](https://share.streamlit.io)
2. New app → select your repo → `app.py`
3. App Settings → Secrets → paste your `secrets.toml` content
4. Deploy

### 3c. Secrets to set
```toml
OPENAI_API_KEY       = "sk-ant-..."
SERVICENOW_INSTANCE     = "dev12345.service-now.com"
SERVICENOW_USER         = "admin"
SERVICENOW_PASS         = "..."
CONTROL_SSH_HOST        = "your-control-node-public-ip"
CONTROL_SSH_USER        = "opc"
CONTROL_SSH_PRIVATE_KEY = """
-----BEGIN RSA PRIVATE KEY-----
...your control node private key...
-----END RSA PRIVATE KEY-----
"""
```

---

## Part 4 — Oracle Cloud Security List (Firewall)

In Oracle Cloud Console → Networking → VCN → Security Lists:

**Control Node (VM #1) Ingress:**
| Protocol | Port | Source      | Purpose               |
|----------|------|-------------|----------------------|
| TCP      | 22   | 0.0.0.0/0   | SSH from Streamlit   |

**Managed Node (VM #2) Ingress:**
| Protocol | Port | Source            | Purpose               |
|----------|------|-------------------|----------------------|
| TCP      | 22   | Control Node IP   | SSH from Ansible     |

Managed Node does NOT need a public IP — only a private IP is needed since Ansible connects from the Control Node (same VCN).

---

## Demo Walkthrough

| Step | Button | What runs |
|------|--------|-----------|
| 1 | Create Change | ServiceNow POST → CHGxxxxxxx |
| 2 | Run Pre-Check | SSH → Control → `pre_health_check.yml` → Managed Node → JSON |
| 3 | Execute Change | SSH → Control → `apply_change.yml -e scenario=X` → Managed Node |
| 4 | Run Post-Check + Validate | `post_health_check.yml` → diff → OPENAI AI → ServiceNow PATCH |
| — | Cleanup | SSH → Control → kill pids, rm files on Managed Node |

### Scenario outcomes
| Scenario | Root Disk | /tmp | Load | Services | AI Verdict |
|----------|-----------|------|------|----------|------------|
| Small Disk | normal | +50MB | normal | all active | ✅ PASS |
| Large Disk | normal | fills up | normal | all active | ❌ FAIL |
| CPU Stress | normal | normal | spikes | all active | ❌ FAIL |
| Stop Service | normal | normal | normal | chronyd ❌ | ❌ FAIL |
