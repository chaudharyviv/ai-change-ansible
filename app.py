"""
app.py — AI Change Governance Platform (GitHub Actions Edition)
"""

import streamlit as st
import json
from engine import (
    create_change, update_change, attach_file,
    run_pre_health_check, run_apply_change,
    run_post_health_check, run_cleanup,
    compare, risk_score, ai_validate,
)

st.set_page_config(
    page_title="AI Change Governance",
    page_icon="🧠",
    layout="wide",
)

st.title("🧠 AI Change Governance Platform")
st.caption("Ansible · GitHub Actions · OPENAI · ServiceNow · Oracle Cloud")

# ── Session state ─────────────────────────────────────────────────────────────

for k, v in {
    "change":        None,
    "pre":           None,
    "pre_run":       None,
    "post":          None,
    "post_run":      None,
    "diff":          None,
    "risk":          None,
    "final":         None,
    "scenario":      None,
    "change_applied": None,
    "apply_run":     None,
}.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.header("📋 Workflow Status")
    steps = [
        ("1. Change Created",       st.session_state.change        is not None),
        ("2. Pre-Check (Actions)",  st.session_state.pre           is not None),
        ("3. Change Applied",       st.session_state.change_applied is not None),
        ("4. Post-Check (Actions)", st.session_state.post          is not None),
        ("5. AI Validated",         st.session_state.final         is not None),
    ]
    for label, done in steps:
        st.write(f"{'✅' if done else '⬜'} {label}")

    st.divider()
    if st.session_state.change:
        st.write(f"**Change:** `{st.session_state.change['number']}`")
    if st.session_state.final:
        v = st.session_state.final["verdict"]
        (st.success if v == "PASS" else st.error)(f"{'✅' if v=='PASS' else '❌'} {v}")

    st.divider()
    st.caption(
        "**Flow**\n\n"
        "```\n"
        "Streamlit\n"
        "  │ GitHub API\n"
        "  ▼\n"
        "GHA Runner (7GB)\n"
        "  │ ansible-playbook\n"
        "  │ SSH\n"
        "  ▼\n"
        "Oracle VM 1GB\n"
        "  (managed node)\n"
        "```"
    )

# ── Step 1: Create Change ─────────────────────────────────────────────────────

st.header("1️⃣ Create Change Request")

col1, col2 = st.columns([2, 3])
with col1:
    if st.button("🎫 Create Change in ServiceNow", use_container_width=True):
        with st.spinner("Creating..."):
            try:
                st.session_state.change = create_change()
                st.success(f"✅ **{st.session_state.change['number']}** created")
            except Exception as e:
                st.error(f"❌ {e}")
with col2:
    if st.session_state.change:
        st.info(f"**{st.session_state.change['number']}** | `{st.session_state.change['sys_id']}`")

# ADD DEBUG HERE
        st.write("DEBUG Change Object:", st.session_state.change)

# ── Step 2: Pre-Check ─────────────────────────────────────────────────────────

st.header("2️⃣ Pre-Change Health Check")
st.caption("Triggers `pre_health_check.yml` via GitHub Actions → Ansible → Oracle VM")

if not st.session_state.change:
    st.warning("⬆️ Complete Step 1 first.")
else:
    if st.button("📸 Trigger Pre-Check Workflow", use_container_width=False):
        try:
            with st.status("Running GitHub Actions workflow...", expanded=True) as status:
                st.write("🚀 Dispatching `pre_health_check.yml` to GitHub Actions...")
                pre, run_info = run_pre_health_check(st.session_state.change["number"])
                st.session_state.pre     = pre
                st.session_state.pre_run = run_info
                st.write(f"✅ Workflow complete in {run_info['elapsed']}s")
                st.write(f"📎 [View Actions run]({run_info['url']})")
                status.update(label="Pre-check complete", state="complete")

            update_change(
                st.session_state.change["sys_id"],
                f"PRE-CHANGE baseline captured via Ansible/GitHub Actions.\n"
                f"Host: {pre['hostname']} | Root: {pre['disk']['root']['used_percent']}% "
                f"| /tmp: {pre['disk']['tmp']['used_percent']}% "
                f"| Load: {pre['load_1m']} | Mem: {pre['memory']['used_percent']}%\n"
                f"Warnings: {len(pre.get('warnings', []))}\n"
                f"Actions run: {run_info['url']}",
                state="-4",
            )
            attach_file(st.session_state.change["sys_id"], "pre_health.json", pre)

        except Exception as e:
            st.error(f"❌ {e}")

    if st.session_state.pre:
        with st.expander("📊 Pre-Check Results", expanded=True):
            p = st.session_state.pre
            c1, c2, c3, c4, c5 = st.columns(5)
            c1.metric("Host",      p.get("hostname", "—"))
            c2.metric("Root Disk", f"{p['disk']['root']['used_percent']}%")
            c3.metric("/tmp",      f"{p['disk']['tmp']['used_percent']}%")
            c4.metric("Load 1m",   str(p.get("load_1m", "—")))
            c5.metric("Memory",    f"{p['memory']['used_percent']}%")

            if p.get("warnings"):
                st.warning("⚠️ " + " | ".join(p["warnings"]))

            col_l, col_r = st.columns(2)
            with col_l:
                st.write("**Services**")
                for svc, state in p.get("services", {}).items():
                    st.write(f"{'🟢' if state == 'active' else '🔴'} `{svc}`: {state}")
            with col_r:
                st.write("**Disk (all)**")
                st.code(p["disk"]["all"], language=None)

            if st.session_state.pre_run:
                st.caption(
                    f"GitHub Actions run: [{st.session_state.pre_run['run_id']}]"
                    f"({st.session_state.pre_run['url']}) — "
                    f"{st.session_state.pre_run['elapsed']}s"
                )

# ── Step 3: Apply Change ──────────────────────────────────────────────────────

st.header("3️⃣ Apply Change Scenario")
st.caption("Triggers `apply_change.yml` via GitHub Actions → Ansible → Oracle VM")

if not st.session_state.pre:
    st.warning("⬆️ Complete Step 2 first.")
else:
    scenarios = {
        "Small Disk (PASS)":      "Writes 50MB to /tmp — system stays healthy → AI: PASS",
        "Large Disk Fill (FAIL)": "Writes 2GB to /tmp — disk fills up → AI: FAIL",
        "CPU Stress (FAIL)":      "4 `yes` processes spike load → AI: FAIL",
        "Stop a Service (FAIL)":  "Stops chronyd → service inactive → AI: FAIL",
    }
    scenario = st.selectbox("Choose Scenario", list(scenarios.keys()))
    st.caption(f"ℹ️ {scenarios[scenario]}")

    if st.button("⚡ Trigger Change Workflow", use_container_width=False):
        try:
            with st.status("Running GitHub Actions workflow...", expanded=True) as status:
                st.write(f"🚀 Dispatching `apply_change.yml` (scenario: {scenario})...")
                result, run_info = run_apply_change(scenario, st.session_state.change["number"])
                st.session_state.change_applied = result
                st.session_state.scenario       = scenario
                st.session_state.apply_run      = run_info
                st.write(f"✅ Workflow complete in {run_info['elapsed']}s")
                st.write(f"📎 [View Actions run]({run_info['url']})")
                status.update(label="Change applied", state="complete")

            st.success(
                f"Root: {result.get('immediate_root_pct')}% | "
                f"/tmp: {result.get('immediate_tmp_pct')}% | "
                f"Load: {result.get('immediate_load_1m')}"
            )
            update_change(
                st.session_state.change["sys_id"],
                f"Change scenario executed: {scenario}\n"
                f"Expected verdict: {result.get('expected_verdict')}\n"
                f"Actions run: {run_info['url']}",
            )
        except Exception as e:
            st.error(f"❌ {e}")

# ── Step 4: Post-Check + AI Validation ───────────────────────────────────────

st.header("4️⃣ Post-Check + AI Validation")
st.caption("Triggers `post_health_check.yml` → computes diff → OPENAI AI → ServiceNow")

if not st.session_state.change_applied:
    st.warning("⬆️ Complete Step 3 first.")
else:
    if st.button("🔍 Trigger Post-Check + Validate", use_container_width=False):

        # Post health check
        try:
            with st.status("Running post-check workflow...", expanded=True) as status:
                st.write("🚀 Dispatching `post_health_check.yml`...")
                post, run_info = run_post_health_check(st.session_state.change["number"])
                st.session_state.post     = post
                st.session_state.post_run = run_info
                st.write(f"✅ Done in {run_info['elapsed']}s — [{run_info['run_id']}]({run_info['url']})")
                status.update(label="Post-check complete", state="complete")
        except Exception as e:
            st.error(f"❌ Post-check failed: {e}")
            st.stop()

        # Diff + Risk
        with st.spinner("Computing diff and risk score..."):
            diff = compare(st.session_state.pre, post)
            risk = risk_score(diff)
            st.session_state.diff = diff
            st.session_state.risk = risk

        # AI Validation
        with st.spinner("Sending to OPENAI AI..."):
            try:
                final = ai_validate(
                    st.session_state.pre, post, diff, risk,
                    st.session_state.change,
                )
                st.session_state.final = final
            except Exception as e:
                st.error(f"❌ AI validation failed: {e}")
                st.stop()

        # ServiceNow update
        with st.spinner("Updating ServiceNow..."):
            try:
                update_change(
                    st.session_state.change["sys_id"],
                    f"POST-CHANGE validation complete.\n\n"
                    f"AI Verdict  : {final['verdict']}\n"
                    f"Risk        : {risk['score']}/100 ({risk['severity']})\n"
                    f"Root Disk Δ : +{diff['disk_root_delta']}%\n"
                    f"/tmp Δ      : +{diff['disk_tmp_delta']}%\n"
                    f"Load Δ      : {diff['load_delta']:+.2f}\n"
                    f"Svc Changes : {len(diff['service_changes'])}\n\n"
                    f"--- AI Work Notes ---\n{final['sn_notes']}\n\n"
                    f"--- Full Analysis ---\n{final['full_analysis']}",
                    state="3" if final["verdict"] == "PASS" else "2",
                )
                attach_file(st.session_state.change["sys_id"], "post_health.json", post)
                attach_file(
                    st.session_state.change["sys_id"],
                    "validation_report.json",
                    {"diff": diff, "risk": risk, "ai": final},
                )
                st.success("✅ ServiceNow updated · JSON files attached.")
            except Exception as e:
                st.warning(f"⚠️ ServiceNow update failed: {e}")

# ── Results ───────────────────────────────────────────────────────────────────

if st.session_state.final:
    st.divider()
    st.header("📊 Validation Results")

    verdict = st.session_state.final["verdict"]
    (st.success if verdict == "PASS" else st.error)(f"## {'✅' if verdict=='PASS' else '❌'}  VALIDATION: {verdict}")

    diff = st.session_state.diff
    risk = st.session_state.risk
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Risk Score",  f"{risk['score']}/100")
    c2.metric("Severity",    risk["severity"])
    c3.metric("Root Disk",   f"{diff['disk_root_after']}%",  f"{diff['disk_root_delta']:+d}%")
    c4.metric("/tmp",        f"{diff['disk_tmp_after']}%",   f"{diff['disk_tmp_delta']:+d}%")
    c5.metric("Load",        f"{diff['load_after']}",        f"{diff['load_delta']:+.2f}")
    c6.metric("Svc Changes", len(diff["service_changes"]))

    if risk["reasons"]:
        st.subheader("⚠️ Risk Factors")
        for r in risk["reasons"]:
            st.write(f"• {r}")

    if diff["service_changes"]:
        st.subheader("⚙️ Service Changes")
        for svc, chg in diff["service_changes"].items():
            bi = "🟢" if chg["before"] == "active" else "🔴"
            ai = "🟢" if chg["after"]  == "active" else "🔴"
            st.write(f"`{svc}`: {bi} {chg['before']} → {ai} {chg['after']}")

    with st.expander("📝 ServiceNow Work Notes (AI-written)", expanded=True):
        st.info(st.session_state.final["sn_notes"])

    with st.expander("🤖 Full OPENAI AI Analysis"):
        st.markdown(st.session_state.final["full_analysis"])
        st.caption(f"Model: `{st.session_state.final.get('model','')}` | Tokens: `{st.session_state.final.get('tokens','')}`")

    with st.expander("📥 Download Full Report"):
        report = {
            "change":        st.session_state.change,
            "scenario":      st.session_state.scenario,
            "pre_health":    {k: v for k, v in st.session_state.pre.items()  if not k.startswith("_")},
            "post_health":   {k: v for k, v in st.session_state.post.items() if not k.startswith("_")},
            "diff":          st.session_state.diff,
            "risk":          st.session_state.risk,
            "ai_result":     st.session_state.final,
            "actions_runs":  {
                "pre":   st.session_state.pre_run,
                "apply": st.session_state.apply_run,
                "post":  st.session_state.post_run,
            },
        }
        st.download_button(
            "⬇️ Download validation_report.json",
            data=json.dumps(report, indent=2),
            file_name="validation_report.json",
            mime="application/json",
        )

# ── Cleanup ───────────────────────────────────────────────────────────────────

st.divider()
st.header("🧹 Cleanup")
st.caption("Triggers `cleanup.yml` via GitHub Actions to restore the Oracle VM.")

if st.button("🗑️ Trigger Cleanup Workflow", type="secondary"):
    scenario = st.session_state.scenario or "small_disk"
    with st.spinner("Running cleanup workflow..."):
        try:
            result = run_cleanup(scenario)
            st.success(f"✅ Cleanup complete — [{result['run_id']}]({result['url']})")
        except Exception as e:
            st.error(f"❌ {e}")
