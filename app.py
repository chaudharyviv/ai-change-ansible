"""
app.py — AI Change Governance Platform
=========================================================
Streamlit UI — zero system calls here.
All execution happens on Oracle VMs via engine.py.
"""

import streamlit as st
import json
from engine import (
    create_change, update_change, attach_file,
    pre_health_check, apply_change, post_health_check,
    compare, risk_score, ai_validate, cleanup,
)

# ══════════════════════════════════════════════════════════════════════════════
# PAGE CONFIG
# ══════════════════════════════════════════════════════════════════════════════

st.set_page_config(
    page_title="AI Change Governance",
    page_icon="🧠",
    layout="wide",
)

st.title("🧠 AI Change Governance Platform")
st.caption("Ansible Playbooks · OPENAI · ServiceNow PDI · Oracle Cloud")

# ══════════════════════════════════════════════════════════════════════════════
# SESSION STATE
# ══════════════════════════════════════════════════════════════════════════════

for k, v in {
    "change":   None,
    "pre":      None,
    "post":     None,
    "diff":     None,
    "risk":     None,
    "final":    None,
    "scenario": None,
    "change_applied": None,
}.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ══════════════════════════════════════════════════════════════════════════════
# SIDEBAR — live status + architecture diagram
# ══════════════════════════════════════════════════════════════════════════════

with st.sidebar:
    st.header("📋 Workflow Status")

    steps = [
        ("1. Change Created",       st.session_state.change   is not None),
        ("2. Pre-Check (Ansible)",  st.session_state.pre      is not None),
        ("3. Change Applied",       st.session_state.change_applied is not None),
        ("4. Post-Check (Ansible)", st.session_state.post     is not None),
        ("5. AI Validated",         st.session_state.final    is not None),
    ]
    for label, done in steps:
        st.write(f"{'✅' if done else '⬜'} {label}")

    st.divider()

    if st.session_state.change:
        st.write(f"**Change:** `{st.session_state.change['number']}`")

    if st.session_state.final:
        v = st.session_state.final["verdict"]
        (st.success if v == "PASS" else st.error)(f"Verdict: {'✅' if v == 'PASS' else '❌'} {v}")
        st.caption(f"Model: `{st.session_state.final.get('model','')}`")
        st.caption(f"Tokens: `{st.session_state.final.get('tokens','')}`")

    st.divider()
    st.caption(
        "**Architecture**\n\n"
        "```\n"
        "Streamlit Cloud\n"
        "  │ SSH\n"
        "  ▼\n"
        "Control Node (VM #1)\n"
        "  │ ansible-playbook\n"
        "  ▼\n"
        "Managed Node (VM #2)\n"
        "  └─ pre_health_check.yml\n"
        "  └─ apply_change.yml\n"
        "  └─ post_health_check.yml\n"
        "```"
    )

# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 — Create Change
# ══════════════════════════════════════════════════════════════════════════════

st.header("1️⃣ Create Change Request")

col1, col2 = st.columns([2, 3])
with col1:
    if st.button("🎫 Create Change in ServiceNow", use_container_width=True):
        with st.spinner("Creating ServiceNow change request..."):
            try:
                st.session_state.change = create_change()
                st.success(f"✅ Created: **{st.session_state.change['number']}**")
            except Exception as e:
                st.error(f"❌ {e}")

with col2:
    if st.session_state.change:
        st.info(
            f"**{st.session_state.change['number']}** — "
            f"`sys_id: {st.session_state.change['sys_id']}`"
        )

# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 — Pre-Change Health Check (Ansible)
# ══════════════════════════════════════════════════════════════════════════════

st.header("2️⃣ Pre-Change Health Check")
st.caption("Runs `pre_health_check.yml` on the Managed Node via the Control Node.")

if st.session_state.change is None:
    st.warning("⬆️ Complete Step 1 first.")
else:
    if st.button("📸 Run Pre-Check Playbook", use_container_width=False):
        with st.spinner("SSH → Control Node → ansible-playbook pre_health_check.yml ..."):
            try:
                pre = pre_health_check()
                st.session_state.pre = pre

                update_change(
                    st.session_state.change["sys_id"],
                    f"PRE-CHANGE baseline captured via Ansible at {pre['timestamp']}.\n"
                    f"Host: {pre['hostname']} | Root Disk: {pre['disk']['root']['used_percent']}% "
                    f"| Load: {pre['load_1m']} | Memory: {pre['memory']['used_percent']}%\n"
                    f"Warnings: {len(pre.get('warnings', []))}",
                    state="-4",
                )
                attach_file(st.session_state.change["sys_id"], "pre_health.json", pre)
                st.success("✅ Pre-check complete — baseline saved to ServiceNow.")
            except Exception as e:
                st.error(f"❌ {e}")

    if st.session_state.pre:
        with st.expander("📊 Pre-Check Results", expanded=True):
            p = st.session_state.pre
            c1, c2, c3, c4, c5 = st.columns(5)
            c1.metric("Host",       p.get("hostname", "—"))
            c2.metric("Root Disk",  f"{p['disk']['root']['used_percent']}%")
            c3.metric("/tmp Disk",  f"{p['disk']['tmp']['used_percent']}%")
            c4.metric("Load (1m)",  str(p.get("load_1m", "—")))
            c5.metric("Memory",     f"{p['memory']['used_percent']}%")

            if p.get("warnings"):
                st.warning("⚠️ Pre-change warnings: " + " | ".join(p["warnings"]))

            col_l, col_r = st.columns(2)
            with col_l:
                st.text("── Services ──────────────────────")
                for svc, state in p.get("services", {}).items():
                    icon = "🟢" if state == "active" else "🔴"
                    st.write(f"{icon} `{svc}`: {state}")
            with col_r:
                st.text("── Disk (all) ────────────────────")
                st.code(p["disk"]["all"], language=None)

            with st.expander("📄 Ansible playbook stdout"):
                st.code(
                    p.get("_ansible_run", {}).get("stdout", ""),
                    language="text"
                )

# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 — Apply Change Scenario
# ══════════════════════════════════════════════════════════════════════════════

st.header("3️⃣ Apply Change Scenario")
st.caption("Runs `apply_change.yml` on the Managed Node with the selected scenario.")

if st.session_state.pre is None:
    st.warning("⬆️ Complete Step 2 first.")
else:
    scenarios = {
        "Small Disk (PASS)":      "Writes 50MB to /tmp — disk stays healthy. AI → PASS.",
        "Large Disk Fill (FAIL)": "Writes 2GB to /tmp — /tmp fills up. AI → FAIL.",
        "CPU Stress (FAIL)":      "Spawns 4 `yes` processes — load spikes. AI → FAIL.",
        "Stop a Service (FAIL)":  "Stops `chronyd` — service goes inactive. AI → FAIL.",
    }

    scenario = st.selectbox("Choose Scenario", list(scenarios.keys()))
    st.caption(f"ℹ️ {scenarios[scenario]}")

    if st.button("⚡ Execute Change Playbook", use_container_width=False):
        with st.spinner(f"ansible-playbook apply_change.yml -e scenario={scenario} ..."):
            try:
                result = apply_change(scenario)
                st.session_state.change_applied = result
                st.session_state.scenario       = scenario
                st.success(
                    f"✅ Change applied — "
                    f"Root: {result.get('immediate_root_pct')}% | "
                    f"/tmp: {result.get('immediate_tmp_pct')}% | "
                    f"Load: {result.get('immediate_load_1m')}"
                )

                update_change(
                    st.session_state.change["sys_id"],
                    f"Change scenario executed: {scenario}\n"
                    f"Expected verdict: {result.get('expected_verdict')}\n"
                    f"Immediate disk: {result.get('immediate_root_pct')}% | "
                    f"Load: {result.get('immediate_load_1m')}",
                )

                with st.expander("📄 Ansible apply_change.yml stdout"):
                    st.code(result.get("_ansible_run", {}).get("stdout", ""), language="text")

            except Exception as e:
                st.error(f"❌ {e}")

# ══════════════════════════════════════════════════════════════════════════════
# STEP 4 — Post-Check + AI Validation
# ══════════════════════════════════════════════════════════════════════════════

st.header("4️⃣ Post-Check + AI Validation")
st.caption("Runs `post_health_check.yml`, computes diff, sends to OPENAI, updates ServiceNow.")

if st.session_state.change_applied is None:
    st.warning("⬆️ Complete Step 3 first.")
else:
    if st.button("🔍 Run Post-Check + Validate", use_container_width=False):

        with st.spinner("ansible-playbook post_health_check.yml ..."):
            try:
                post = post_health_check()
                st.session_state.post = post
            except Exception as e:
                st.error(f"❌ Post-check failed: {e}")
                st.stop()

        with st.spinner("Computing diff..."):
            diff = compare(st.session_state.pre, post)
            risk = risk_score(diff)
            st.session_state.diff = diff
            st.session_state.risk = risk

        with st.spinner("Sending Ansible output to OPENAI AI..."):
            try:
                final = ai_validate(
                    st.session_state.pre,
                    post,
                    diff,
                    risk,
                    st.session_state.change,
                )
                st.session_state.final = final
            except Exception as e:
                st.error(f"❌ AI validation failed: {e}")
                st.stop()

        with st.spinner("Updating ServiceNow..."):
            try:
                new_state = "3" if final["verdict"] == "PASS" else "2"
                update_change(
                    st.session_state.change["sys_id"],
                    f"POST-CHANGE validation complete.\n\n"
                    f"AI Verdict  : {final['verdict']}\n"
                    f"Risk Score  : {risk['score']}/100 ({risk['severity']})\n"
                    f"Disk Root Δ : +{diff['disk_root_delta']}%\n"
                    f"Disk /tmp Δ : +{diff['disk_tmp_delta']}%\n"
                    f"Load Δ      : {diff['load_delta']:+.2f}\n"
                    f"Svc Changes : {len(diff['service_changes'])}\n\n"
                    f"--- AI Work Notes ---\n{final['sn_notes']}\n\n"
                    f"--- Full Analysis ---\n{final['full_analysis']}",
                    state=new_state,
                )
                attach_file(st.session_state.change["sys_id"], "post_health.json", post)
                attach_file(
                    st.session_state.change["sys_id"],
                    "validation_report.json",
                    {"diff": diff, "risk": risk, "ai": final},
                )
                st.success("✅ ServiceNow updated · 2 JSON files attached.")
            except Exception as e:
                st.warning(f"⚠️ ServiceNow update failed (results still shown below): {e}")

# ══════════════════════════════════════════════════════════════════════════════
# RESULTS
# ══════════════════════════════════════════════════════════════════════════════

if st.session_state.final:

    st.divider()
    st.header("📊 Validation Results")

    verdict = st.session_state.final["verdict"]
    if verdict == "PASS":
        st.success(f"## ✅  VALIDATION: PASS")
    else:
        st.error(f"## ❌  VALIDATION: FAIL")

    # Key metrics
    diff = st.session_state.diff
    risk = st.session_state.risk
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Risk Score",    f"{risk['score']}/100")
    c2.metric("Severity",      risk["severity"])
    c3.metric("Root Disk",     f"{diff['disk_root_after']}%",  f"{diff['disk_root_delta']:+d}%")
    c4.metric("/tmp Disk",     f"{diff['disk_tmp_after']}%",   f"{diff['disk_tmp_delta']:+d}%")
    c5.metric("Load (1m)",     f"{diff['load_after']}",        f"{diff['load_delta']:+.2f}")
    c6.metric("Svc Changes",   len(diff["service_changes"]))

    # Risk reasons
    if risk["reasons"]:
        st.subheader("⚠️ Risk Factors Detected")
        for r in risk["reasons"]:
            st.write(f"• {r}")

    # Service changes
    if diff["service_changes"]:
        st.subheader("⚙️ Service State Changes")
        for svc, change in diff["service_changes"].items():
            before_icon = "🟢" if change["before"] == "active" else "🔴"
            after_icon  = "🟢" if change["after"]  == "active" else "🔴"
            st.write(f"`{svc}`: {before_icon} {change['before']} → {after_icon} {change['after']}")

    # ServiceNow work notes (what OPENAI wrote for SN)
    with st.expander("📝 ServiceNow Work Notes (AI-generated)", expanded=True):
        st.info(st.session_state.final["sn_notes"])

    # Full AI analysis
    with st.expander("🤖 Full OPENAI AI Analysis"):
        st.markdown(st.session_state.final["full_analysis"])

    # Ansible stdout from post-check
    if st.session_state.post:
        with st.expander("📄 Ansible post_health_check.yml stdout"):
            st.code(
                st.session_state.post.get("_ansible_run", {}).get("stdout", ""),
                language="text"
            )

    # Download full report
    with st.expander("📥 Download Full Report"):
        report = {
            "change":       st.session_state.change,
            "scenario":     st.session_state.scenario,
            "pre_health":   {k: v for k, v in st.session_state.pre.items()  if k != "_ansible_run"},
            "post_health":  {k: v for k, v in st.session_state.post.items() if k != "_ansible_run"},
            "diff":         st.session_state.diff,
            "risk":         st.session_state.risk,
            "ai_result":    st.session_state.final,
        }
        st.download_button(
            label="⬇️ Download validation_report.json",
            data=json.dumps(report, indent=2),
            file_name="validation_report.json",
            mime="application/json",
        )

# ══════════════════════════════════════════════════════════════════════════════
# CLEANUP
# ══════════════════════════════════════════════════════════════════════════════

st.divider()
st.header("🧹 Cleanup")
st.caption("Removes temp files and restores services on the Managed Node.")

if st.button("🗑️ Cleanup Managed Node", type="secondary"):
    scenario = st.session_state.scenario or ""
    with st.spinner("Cleaning up..."):
        try:
            results = cleanup(scenario)
            st.success("✅ Managed Node restored.")
        except Exception as e:
            st.error(f"❌ Cleanup error: {e}")
