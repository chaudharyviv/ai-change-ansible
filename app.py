"""
app.py — AI Change Governance Platform (Enterprise Safe Version)
"""

import streamlit as st
import json
from engine import (
    create_change, update_change, attach_file,
    run_pre_health_check, run_apply_change,
    run_post_health_check, run_cleanup,
    compare, risk_score, ai_validate,
    ai_precheck_assessment,
)

st.set_page_config(
    page_title="AI Change Governance",
    page_icon="🧠",
    layout="wide",
)

st.title("🧠 AI Change Governance Platform")
st.caption("Ansible · GitHub Actions · OPENAI · ServiceNow · Oracle Cloud")

# ─────────────────────────────────────────────────────────────
# Session Initialization
# ─────────────────────────────────────────────────────────────

DEFAULTS = {
    "change": None,
    "change_lock": None,
    "pre": None,
    "pre_run": None,
    "post": None,
    "post_run": None,
    "diff": None,
    "risk": None,
    "final": None,
    "scenario": None,
    "change_applied": None,
    "apply_run": None,
}

for k, v in DEFAULTS.items():
    if k not in st.session_state:
        st.session_state[k] = v


# ─────────────────────────────────────────────────────────────
# Validation Helpers
# ─────────────────────────────────────────────────────────────

def validate_active_change():
    if not st.session_state.get("change"):
        st.error("No active ServiceNow change in session.")
        st.stop()

    if "sys_id" not in st.session_state.change:
        st.error("Invalid change object detected.")
        st.stop()

    if st.session_state.change_lock and \
       st.session_state.change["sys_id"] != st.session_state.change_lock:
        st.error("Change mismatch detected. Session invalid.")
        st.stop()


# ─────────────────────────────────────────────────────────────
# Sidebar Status
# ─────────────────────────────────────────────────────────────

with st.sidebar:
    st.header("📋 Workflow Status")

    steps = [
        ("1. Change Created", st.session_state.change is not None),
        ("2. Pre-Check", st.session_state.pre is not None),
        ("3. Change Applied", st.session_state.change_applied is not None),
        ("4. Post-Check", st.session_state.post is not None),
        ("5. AI Validated", st.session_state.final is not None),
    ]

    for label, done in steps:
        st.write(f"{'✅' if done else '⬜'} {label}")

    st.divider()

    if st.session_state.change:
        st.write(f"**Change:** `{st.session_state.change['number']}`")

    if st.session_state.final:
        verdict = st.session_state.final["verdict"]
        (st.success if verdict == "PASS" else st.error)(
            f"{'✅' if verdict=='PASS' else '❌'} {verdict}"
        )


# ─────────────────────────────────────────────────────────────
# 1️⃣ Create Change
# ─────────────────────────────────────────────────────────────

st.header("1️⃣ Create Change Request")

if not st.session_state.change:
    if st.button("🎫 Create Change in ServiceNow"):
        try:
            change = create_change()
            st.session_state.change = change
            st.session_state.change_lock = change["sys_id"]
            st.success(f"✅ Change {change['number']} created.")
        except Exception as e:
            st.error(f"❌ Failed to create change: {e}")
else:
    st.info(f"Active Change: {st.session_state.change['number']}")


# ─────────────────────────────────────────────────────────────
# 2️⃣ Pre-Check
# ─────────────────────────────────────────────────────────────

st.header("2️⃣ Pre-Change Health Check")

if not st.session_state.change:
    st.warning("Create a change first.")
else:
    if st.button("📸 Run Pre-Check"):
        validate_active_change()

        try:
            pre, run_info = run_pre_health_check(
                st.session_state.change["number"]
            )
            st.session_state.pre = pre
            st.session_state.pre_run = run_info

            # AI PRECHECK GATE
            gate = ai_precheck_assessment(pre)
            if not gate["proceed"]:
                st.error(f"Pre-check failed: {gate['reason']}")
                st.stop()

            update_change(
                st.session_state.change["sys_id"],
                f"Pre-check completed successfully.\n"
                f"GitHub Run: {run_info['url']}",
            )

            attach_file(
                st.session_state.change["sys_id"],
                "pre_health.json",
                pre,
            )

            st.success("Pre-check completed.")

        except Exception as e:
            st.error(f"❌ Pre-check failed: {e}")
            st.stop()

    if st.session_state.pre:
        p = st.session_state.pre
        root_pct = p.get("disk", {}).get("root", {}).get("used_percent", "N/A")
        tmp_pct = p.get("disk", {}).get("tmp", {}).get("used_percent", "N/A")

        col1, col2 = st.columns(2)
        col1.metric("Root Disk", f"{root_pct}%")
        col2.metric("/tmp", f"{tmp_pct}%")


# ─────────────────────────────────────────────────────────────
# 3️⃣ Apply Change
# ─────────────────────────────────────────────────────────────

st.header("3️⃣ Apply Change Scenario")

if not st.session_state.pre:
    st.warning("Run Pre-check first.")
else:
    scenario = st.selectbox(
        "Choose Scenario",
        [
            "Small Disk (PASS)",
            "Large Disk Fill (FAIL)",
            "CPU Stress (FAIL)",
            "Stop a Service (FAIL)",
        ],
    )

    if st.button("⚡ Apply Change"):
        validate_active_change()

        try:
            result, run_info = run_apply_change(
                scenario,
                st.session_state.change["number"]
            )

            st.session_state.change_applied = result
            st.session_state.scenario = scenario
            st.session_state.apply_run = run_info

            update_change(
                st.session_state.change["sys_id"],
                f"Scenario executed: {scenario}\n"
                f"GitHub Run: {run_info['url']}",
            )

            st.success("Change applied successfully.")

        except Exception as e:
            st.error(f"❌ Change failed: {e}")
            st.stop()


# ─────────────────────────────────────────────────────────────
# 4️⃣ Post-Check + AI Validation
# ─────────────────────────────────────────────────────────────

st.header("4️⃣ Post-Check + AI Validation")

if not st.session_state.change_applied:
    st.warning("Apply change first.")
else:
    if st.button("🔍 Validate Change"):
        validate_active_change()

        try:
            post, run_info = run_post_health_check(
                st.session_state.change["number"]
            )
            st.session_state.post = post
            st.session_state.post_run = run_info

            diff = compare(st.session_state.pre, post)
            risk = risk_score(diff)

            st.session_state.diff = diff
            st.session_state.risk = risk

            final = ai_validate(
                st.session_state.pre,
                post,
                diff,
                risk,
                st.session_state.change,
            )

            st.session_state.final = final

            update_change(
                st.session_state.change["sys_id"],
                f"Post-validation completed.\n"
                f"Verdict: {final['verdict']}\n"
                f"Risk Score: {risk['score']} ({risk['severity']})",
            )

            attach_file(
                st.session_state.change["sys_id"],
                "post_health.json",
                post,
            )

            attach_file(
                st.session_state.change["sys_id"],
                "validation_report.json",
                {
                    "diff": diff,
                    "risk": risk,
                    "ai": final,
                },
            )

            # AUTO ROLLBACK IF FAIL
            if final["verdict"] == "FAIL":
                run_cleanup(st.session_state.scenario)
                st.warning("Automatic rollback executed.")

            st.success(f"Validation: {final['verdict']}")

        except Exception as e:
            st.error(f"❌ Validation failed: {e}")
            st.stop()


# ─────────────────────────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────────────────────────

st.divider()
st.header("🧹 Manual Cleanup")

if st.button("Run Cleanup"):
    validate_active_change()

    try:
        result = run_cleanup(st.session_state.scenario or "Small Disk (PASS)")
        st.success(f"Cleanup completed: {result['conclusion']}")
    except Exception as e:
        st.error(f"❌ Cleanup failed: {e}")