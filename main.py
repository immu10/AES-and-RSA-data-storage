# main.py (refactored to use role-based RSA+AES decryption)

import streamlit as st
from login import verify_login, get_user_attributes, can_user_write
from create_user import create_user
from data import encrypt_data, decrypt_data
import json
import pandas as pd
from datetime import datetime


st.set_page_config(page_title="Secure Health Records", layout="centered")
st.title("Secure Health Record System")
# use the key below in actual real world cases......
# REGISTRATION_OVERRIDE_CODE = "Y92qJrT5WCuMvhgZqDP14rNt6FEaMbyLGgKePzXvAaSbrQNH7fBjTLyZuOmXpCvQWMEJ82Gt5ya49uUX3ZrNK1aYJ4BCfwxiMpdhOeR0tgscHz6A7ldkoEvDCpMNzYBJ"
REGISTRATION_OVERRIDE_CODE = "letmein123"

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = ""

menu_items = ["Login", "Sign Up", "Encrypt", "Decrypt"]
if st.session_state.get("logged_in") and "Admin" in get_user_attributes(st.session_state["username"]):
    menu_items.append("Admin Panel")
if st.session_state.get("logged_in") and "Admin" in get_user_attributes(st.session_state["username"]):
    menu_items.append("Dashboard")
menu = st.sidebar.selectbox("Navigation", menu_items)
if st.session_state.get("logged_in", False):
    if st.sidebar.button("🚪 Logout"):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.success("Logged out successfully")
        st.rerun()  #  refresh immediately
# -------------------- LOGIN --------------------
if menu == "Login":
    st.header("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if "login_submitted" not in st.session_state:
        st.session_state.login_submitted = False

    if st.button("Login"):
        st.session_state.login_submitted = True

    if st.session_state.login_submitted:
        if verify_login(username, password):
            st.session_state.logged_in = True
            st.session_state.username = username
            st.success(f"Logged in as {username}")
            st.rerun()  #  force re-render with new session state
        else:
            st.error("Invalid credentials")
            st.session_state.login_submitted = False

# -------------------- SIGN UP --------------------

elif menu == "Sign Up":
    st.header("Create Account")

    # First: Check access
    is_logged_in = st.session_state.get("logged_in", False)
    is_admin = "Admin" in get_user_attributes(st.session_state["username"]) if is_logged_in else False
    is_override = st.session_state.get("signup_override", False)

    # Gate: show override prompt only if not admin or override already
    if not is_logged_in and not is_override:
        override_input = st.text_input("Enter Admin Override Code", type="password")
        if st.button("Enter"):
            if override_input == REGISTRATION_OVERRIDE_CODE:
                st.session_state.signup_override = True
                st.rerun()  # rerun to show signup fields
            else:
                st.error("Invalid code.")
        st.stop()  # Prevent form from showing until passed

    if is_logged_in and not is_admin:
        st.error("Only Admins can create accounts.")
        st.stop()

    # If we've passed the gate (via override or admin), show signup form:
    username = st.text_input("New Username")
    password = st.text_input("New Password", type="password")
    role = st.selectbox("Role", ["Doctor", "Nurse", "Intern", "Admin"])
    if role in ["Doctor", "Admin", "Nurse"]:
        can_write = True
    else:
        can_write = False

    if st.button("Create Account"):
        result = create_user(username, password, role, can_write)
        if result == "exists":
            st.error("Username already exists")
        else:
            st.success("Account created successfully")
            st.session_state.signup_override = False  # reset after success


# -------------------- ENCRYPT --------------------
elif menu == "Encrypt":
    if not st.session_state.logged_in:
        st.warning("Please login first")
    elif not can_user_write(st.session_state.username):
        st.error("You do not have write permission")
    else:
        st.header("Encrypt Record")
        st.subheader("New Medical Record")

        form_data = {}
        missing_fields = []

        try:
            with open("fields.json", "r") as f:
                fields = json.load(f)

            for field in fields:
                key = field["key"]
                label = field["label"]
                ftype = field["type"]

                if ftype == "text_input":
                    form_data[key] = st.text_input(label)
                elif ftype == "text_area":
                    form_data[key] = st.text_area(label)
                elif ftype == "number_input":
                    form_data[key] = st.number_input(label, min_value=field.get("min", 0), max_value=field.get("max", 100), step=1)
                elif ftype == "selectbox":
                    form_data[key] = st.selectbox(label, field["options"])

                if field.get("required") and not form_data[key]:
                    missing_fields.append(label)

            if st.button("Encrypt Record"):
                if missing_fields:
                    st.warning("Please fill in: " + ", ".join(missing_fields))
                else:
                    record_json = json.dumps(form_data)
                    success, message = encrypt_data(record_json, st.session_state.username)
                    if success:
                        st.success(message)
                    else:
                        st.error("Encryption failed.")
        except Exception as e:
            st.error(f"Could not load form_fields.json: {e}")


# -------------------- DECRYPT --------------------
elif menu == "Decrypt":
    search_query = st.text_input(" Search records by Patient Name or Diagnosis").lower()

    if not st.session_state.logged_in:
        st.warning("Please login first")
    else:
        st.header("Decrypt Records")
        role = get_user_attributes(st.session_state.username)[0]
        success, output = decrypt_data(role)

        if not success:
            st.error(output)
        else:
            if not output:
                st.info("No records found.")
            for author, timestamp, ok, result in output:
                if ok:
                    try:
                        parsed = json.loads(result)
                        if search_query and not (
                            search_query in parsed.get("name", "").lower() or 
                            search_query in parsed.get("diagnosis", "").lower()
                        ):
                            continue

                        st.success(f"🩺 Record by {author} — {timestamp}")
                        st.json(parsed)
                    except:
                        st.success(f"🩺 Record by {author} — {timestamp}")
                        st.code(result)

    # Admin-only: Delete records
    if "Admin" in get_user_attributes(st.session_state.username):
        st.markdown("---")
        st.subheader("Manage Records (Admin Only)")

        try:
            with open("records.txt", "r") as f:
                raw_lines = [line.strip() for line in f if line.strip()]
                record_objs = [json.loads(line) for line in raw_lines]
        except Exception as e:
            st.error("Could not load records.")
            st.stop()

        for i, rec in enumerate(record_objs):
            st.markdown(f"**Record {i + 1} by `{rec['user']}`**")
            col1, col2 = st.columns([6, 1])
            with col1:
                preview = rec.get("data", "")[:70] + "..." if len(rec.get("data", "")) > 70 else rec.get("data", "")
                st.code(preview)
            with col2:
                if st.button(f"Delete", key=f"delete_{i}"):
                    del record_objs[i]
                    with open("records.txt", "w") as f:
                        for r in record_objs:
                            f.write(json.dumps(r) + "\n")
                    st.success(f"Record {i + 1} deleted.")
                    st.rerun()


# -------------------- ADMIN PANEL --------------------

elif menu == "Admin Panel":
    st.header("🛠️ Admin Control Panel")

    try:
        with open("logins.txt", "r") as f:
            users = json.load(f)
    except:
        users = {}

    # Revoke user login
    st.subheader("Revoke User Access")
    usernames = [u for u in users.keys() if u != st.session_state.username]
    selected_user = st.selectbox("Select user to delete", usernames)
    if st.button("Delete User"):
        if selected_user in users:
            del users[selected_user]
            with open("logins.txt", "w") as f:
                json.dump(users, f, indent=2)
            st.success(f"User '{selected_user}' deleted.")
            st.rerun()

    # Toggle write access for interns
    st.markdown("---")
    st.subheader("Manage Intern Write Access")
    interns = [u for u, v in users.items() if "Intern" in v.get("attributes", [])]
    if interns:
        selected_intern = st.selectbox("Choose Intern", interns)
        if selected_intern:
            current = users[selected_intern].get("can_write", False)
            new_value = st.checkbox("Grant Write Access", value=current)
            if st.button("Update Write Access"):
                users[selected_intern]["can_write"] = new_value
                with open("logins.txt", "w") as f:
                    json.dump(users, f, indent=2)
                st.success(f"Updated write access for {selected_intern}")
    else:
        st.info("No interns found.")

# -------------------- DASHBOARD --------------------

elif menu == "Dashboard":
    st.title("System Dashboard")

    try:
        with open("records.txt", "r") as f:
            raw_lines = [line.strip() for line in f if line.strip()]
            records = [json.loads(line) for line in raw_lines]
    except:
        records = []

    try:
        with open("logins.txt", "r") as f:
            users = json.load(f)
    except:
        users = {}

    # Basic stats
    st.metric("Total Records", len(records))
    st.metric("Registered Users", len(users))

    # Records per user
    st.subheader("Records by User")
    user_counts = {}
    for rec in records:
        author = rec.get("user", "Unknown")
        user_counts[author] = user_counts.get(author, 0) + 1

    for user, count in user_counts.items():
        st.write(f"• **{user}**: {count} record(s)")

    # Optional: Timestamp trend
    st.subheader("Records Over Time")
    timestamps = [datetime.fromisoformat(rec["timestamp"]) for rec in records if "timestamp" in rec]

    if timestamps:
        df = pd.DataFrame(timestamps, columns=["timestamp"])
        df["count"] = 1
        df.set_index("timestamp", inplace=True)
        chart_data = df.resample("D").count()
        st.line_chart(chart_data)
    else:
        st.info("No timestamps available to plot.")


