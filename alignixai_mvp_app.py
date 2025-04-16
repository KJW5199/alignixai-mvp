import streamlit as st
import pandas as pd
from datetime import datetime
import base64
import io
import json
import os

st.set_page_config(page_title="AlignixAI - Compliance MVP", layout="wide")

# ---------- DATA PERSISTENCE ----------
APPROVED_SUMMARIES_FILE = "approved_summaries.json"
AUDIT_LOG_FILE = "audit_log.json"
EMPLOYEE_DATA_FILE = "mock_employees.json"


def load_json(filepath, default):
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            return json.load(f)
    return default


def save_json(filepath, data):
    with open(filepath, "w") as f:
        json.dump(data, f, default=str)


def load_employees():
    data = load_json(EMPLOYEE_DATA_FILE, None)
    if data:
        return pd.DataFrame(data)
    else:
        return pd.DataFrame([
            {"Employee ID": "EMP001", "Name": "Sarah Bennett", "Role": "KYC Analyst", "Training": []},
            {"Employee ID": "EMP002", "Name": "James Ormond", "Role": "KYC QC Analyst", "Training": []},
            {"Employee ID": "EMP003", "Name": "Priya Malhotra", "Role": "KYC Analyst", "Training": []},
        ])


def save_employees(df):
    save_json(EMPLOYEE_DATA_FILE, df.to_dict(orient="records"))

# ---------- LOAD DATA ----------
mock_policies = pd.DataFrame([
    {"Policy ID": "POL001", "Title": "KYC Onboarding Update", "Status": "Pending Review", "Last Updated": "2024-12-12", "Version": "1.0", "Notes": ""},
    {"Policy ID": "POL002", "Title": "AML Red Flag List", "Status": "Approved", "Last Updated": "2024-11-02", "Version": "1.0", "Notes": ""},
])

mock_employees = load_employees()
approved_summaries = load_json(APPROVED_SUMMARIES_FILE, {})
audit_log = load_json(AUDIT_LOG_FILE, [])
quiz_results = {}
role_types = mock_employees['Role'].unique().tolist()

# ---------- FUNCTIONS ----------
def show_dashboard():
    st.image("https://via.placeholder.com/150x40?text=AlignixAI+Logo")
    st.title("AlignixAI Compliance Training Dashboard")

    with st.expander("🔧 Admin Controls"):
        if st.button("Reset: All Data"):
            approved_summaries.clear()
            if os.path.exists(APPROVED_SUMMARIES_FILE):
                os.remove(APPROVED_SUMMARIES_FILE)

            audit_log.clear()
            if os.path.exists(AUDIT_LOG_FILE):
                os.remove(AUDIT_LOG_FILE)

            for idx in mock_employees.index:
                mock_employees.at[idx, 'Training'] = []
            save_employees(mock_employees)
            st.success("All data reset.")

    col1, col2, col3 = st.columns(3)
    col1.metric("📝 Pending Policies", sum(mock_policies['Status'] == 'Pending Review'))
    col2.metric("✅ Approved", sum(mock_policies['Status'] == 'Approved'))
    col3.metric("🎯 Employees Assigned Training", sum(mock_employees['Training'].apply(lambda x: len(x) > 0)))

    with st.expander("📑 View All Policies"):
        filter_status = st.selectbox("Filter by Status", options=["All", "Pending Review", "Approved"])
        filtered = mock_policies if filter_status == "All" else mock_policies[mock_policies['Status'] == filter_status]
        st.dataframe(filtered)


    st.markdown(
        "<div style='text-align: center; font-size: 12px; color: grey; margin-top: 40px;'>"
        "🔒 Confidential Prototype – Do not use with real client data"
        "</div>",
        unsafe_allow_html=True
    )
def add_policy_from_file(uploaded_file):
    uploaded_title = uploaded_file.name.split('.')[0]
    if uploaded_title not in mock_policies['Title'].values:
        new_policy = {
            "Policy ID": f"POL{len(mock_policies)+1:03}",
            "Title": uploaded_title,
            "Status": "Pending Review",
            "Last Updated": str(datetime.today().date()),
            "Version": "1.0",
            "Notes": ""
        }
        mock_policies.loc[len(mock_policies)] = new_policy

def show_policy_review():
    st.subheader("📥 Upload & Review Policy Document")

    st.markdown("**⚠️ Test Use Only:** Please do not upload real client or employee data. Use anonymized or sample policies only.")
uploaded_file = st.file_uploader("Upload policy file (PDF or TXT)", type=["txt", "pdf"])
    if uploaded_file:
        add_policy_from_file(uploaded_file)
        file_name = uploaded_file.name.split('.')[0]
        import fitz  # PyMuPDF
        file_content = ""
        if uploaded_file.name.endswith(".pdf"):
            temp_path = "temp_uploaded.pdf"
        with open(temp_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
            with fitz.open("temp_uploaded.pdf") as doc:
                for page in doc:
                file_content += page.get_text()
        else:
            file_content = uploaded_file.read().decode("utf-8", errors="ignore")
        st.text_area("📄 File Content Preview:", file_content[:1000], height=200)
        if os.path.exists(temp_path):
            os.remove(temp_path)
        st.success("File received. You can now generate a training summary manually.")

    pending_titles = mock_policies[mock_policies['Status'] == 'Pending Review']['Title'].tolist()
    if pending_titles:
        selected_policy = st.selectbox("Select Policy to Review", pending_titles)
        summary = file_content[:300] if 'file_content' in locals() else "- Add training summary here."
        scenario = "Based on this policy, what actions must a compliance analyst take to ensure proper escalation?"

        st.markdown(f"**AI Summary for:** `{selected_policy}`")
        st.text_area("Summary:", summary, height=120)
        st.text_area("Scenario:", scenario, height=100)
        notes = st.text_input("Reviewer Notes")

        if st.button("✅ Approve & Generate Training"):
            mock_policies.loc[mock_policies['Title'] == selected_policy, 'Status'] = 'Approved'
            mock_policies.loc[mock_policies['Title'] == selected_policy, 'Notes'] = notes
            approved_summaries[selected_policy] = {"summary": summary, "scenario": scenario}
            audit_log.append((str(datetime.now()), selected_policy, "Approved"))
            save_json(APPROVED_SUMMARIES_FILE, approved_summaries)
            save_json(AUDIT_LOG_FILE, audit_log)
            st.success("Approved and added as training module!")


def show_training_tab():
    st.subheader("🎓 Training Assignment & Progress")

    for title, content in approved_summaries.items():
        with st.expander(f"📘 {title}"):
            st.markdown("### 🟢 Summary")
            st.markdown(content['summary'])
            st.markdown("### 🟨 Scenario")
            st.markdown(content['scenario'])
            st.markdown("### ❓ Quiz")
            choice = st.radio("Your action?", ["Escalate to MLRO", "Ignore alert", "Request ID docs", "Approve without check"], key=title)
            quiz_results[title] = choice
            st.success("✅ Correct!" if choice == "Escalate to MLRO" else "❌ Not correct.")

            role_to_assign = st.selectbox("Assign by Role:", role_types, key=title+"_role")
            if st.button(f"📤 Assign to All {role_to_assign}", key=f"{title}_assign_role"):
                for idx in mock_employees[mock_employees['Role'] == role_to_assign].index:
                    if title not in mock_employees.at[idx, 'Training']:
                        mock_employees.at[idx, 'Training'].append(title)
                st.success(f"Assigned to all {role_to_assign}s")

            selected_employees = st.multiselect("Or assign to individuals:", mock_employees['Name'], key=title+"_manual")
            if st.button(f"Assign Selected for {title}", key=f"{title}_assign_selected"):
                for name in selected_employees:
                    idx = mock_employees[mock_employees['Name'] == name].index[0]
                    if title not in mock_employees.at[idx, 'Training']:
                        mock_employees.at[idx, 'Training'].append(title)
                        audit_log.append((str(datetime.now()), f"Training for {title}", f"Assigned to {name}"))
                st.success("Assigned successfully.")
                save_employees(mock_employees)
                save_json(AUDIT_LOG_FILE, audit_log)

    with st.expander("📋 Download Employee Training Report"):
        all_records = []
        for _, row in mock_employees.iterrows():
            for module in row['Training']:
                all_records.append({"Employee": row['Name'], "Role": row['Role'], "Module": module})
        if all_records:
            df = pd.DataFrame(all_records)
            st.dataframe(df)
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button("📥 Download CSV Report", data=csv, file_name="training_report.csv", mime='text/csv')


def show_user_login():
    st.subheader("👤 Employee Training Portal")
    user = st.selectbox("Log in as employee:", mock_employees['Name'])
    user_row = mock_employees[mock_employees['Name'] == user].iloc[0]
    st.info(f"Logged in as: {user_row['Name']} ({user_row['Role']})")

    assigned = user_row['Training']
    if assigned:
        for module in assigned:
            st.markdown(f"### 📘 {module}")
            if module in approved_summaries:
                st.markdown("#### Summary")
                st.markdown(approved_summaries[module]['summary'])
                st.markdown("#### Scenario")
                st.markdown(approved_summaries[module]['scenario'])

                if st.button(f"✅ Mark {module} as Completed", key=module):
                    idx = mock_employees[mock_employees['Name'] == user].index[0]
                    mock_employees.at[idx, 'Training'].remove(module)
                    audit_log.append((str(datetime.now()), f"Training for {user}", f"Completed: {module}"))
                    save_employees(mock_employees)
                    save_json(AUDIT_LOG_FILE, audit_log)
                    st.success(f"{module} marked as complete")
    else:
        st.warning("No training assigned.")


def show_audit_log():
    st.subheader("📜 Full Audit Trail")
    if not audit_log:
        st.info("No activity logged yet.")
    else:
        for log in audit_log:
            st.markdown(f"`{log[0]}` — **{log[1]}** → {log[2]}")

# ---------- NAV ----------
tabs = st.sidebar.radio("🔎 Navigate:", ["Dashboard", "Policy Review", "Training", "User Portal", "Audit Log"])
st.sidebar.markdown("### 🔒 Disclaimer")
st.sidebar.info(
    "This prototype is for demonstration and testing purposes only. "
    "It is not intended for use with actual client or employee data. "
    "All functionality and concepts are confidential and the property of AlignixAI."
)

if tabs == "Dashboard":
    show_dashboard()
elif tabs == "Policy Review":
    show_policy_review()
elif tabs == "Training":
    show_training_tab()
elif tabs == "User Portal":
    show_user_login()
elif tabs == "Audit Log":
    show_audit_log()
    st.markdown(
        "<div style='text-align: center; font-size: 12px; color: grey; margin-top: 40px;'>"
        "🔒 Confidential Prototype – Do not use with real client data"
        "</div>",
        unsafe_allow_html=True
    )
