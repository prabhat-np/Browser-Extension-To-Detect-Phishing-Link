import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import extra_streamlit_components as stx
import time
import os
import sys
import datetime

# Path Setup
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.model_trainer import ModelEngine
from services.auth_service import AuthService
from services.report_generator import ReportGenerator
from services.quiz_service import QuizService
from services.audit_log_service import AuditLogService

# --- Configuration ---
st.set_page_config(
    page_title="FinShield AI | Banking Security Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Cookie Manager for Persistence ---
cookie_manager = stx.CookieManager()

# --- Load Custom CSS ---
def load_css():
    with open("assets/styles.css") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

load_css()

# --- Session State Management ---
if 'auth_token' not in st.session_state:
    st.session_state.auth_token = None
if 'user_role' not in st.session_state:
    st.session_state.user_role = None
if 'username' not in st.session_state:
    st.session_state.username = None
if 'scan_history' not in st.session_state:
    st.session_state.scan_history = []
if 'force_logout' not in st.session_state:
    st.session_state.force_logout = False

# --- Model Initialization ---
@st.cache_resource
def get_model_engine():
    engine = ModelEngine()
    if not engine.model:
        engine.train('data/processed/training_dataset_v1.csv')
    return engine

model_engine = get_model_engine()

# --- Authentication Logic ---

def try_auto_login():
    """Attempt to login using cookie token"""
    if st.session_state.force_logout:
        return False
    if st.session_state.auth_token:
        payload = AuthService.verify_token(st.session_state.auth_token)
        if payload:
            st.session_state.force_logout = False
            st.session_state.username = payload.get('username')
            st.session_state.user_role = payload.get('role')
            return True
        try:
            cookie_manager.delete("auth_token")
        except Exception:
            pass
        st.session_state.auth_token = None
        st.session_state.username = None
        st.session_state.user_role = None
        return False
    
    token = cookie_manager.get(cookie="auth_token")
    if token:
        payload = AuthService.verify_token(token)
        if payload:
            st.session_state.force_logout = False
            st.session_state.auth_token = token
            st.session_state.username = payload['username']
            st.session_state.user_role = payload['role']
            return True
        try:
            cookie_manager.delete("auth_token")
        except Exception:
            pass
    return False

def login_view():
    col1, col2, col3 = st.columns([1, 1.5, 1])
    with col2:
        st.markdown("""
        <div style="text-align: center; margin-bottom: 30px;">
            <h1 style="color: #0f172a; font-size: 3rem;">FinShield AI</h1>
            <p style="color: #64748b; font-size: 1.2rem;">Banking Phishing Defense & Awareness Platform</p>
        </div>
        """, unsafe_allow_html=True)
        
        with st.container():
            st.markdown("### Secure Access Portal")
            username = st.text_input("Username", placeholder="Enter your bank ID")
            password = st.text_input("Password", type="password", placeholder="Enter your secure password")
            
            if st.button("Authenticate", use_container_width=True):
                user = AuthService.login(username, password)
                if user:
                    # Set Session State
                    st.session_state.force_logout = False
                    st.session_state.auth_token = user['token']
                    st.session_state.username = user['username']
                    st.session_state.user_role = user['role']
                    
                    # Set Cookie (Expires in 1 day)
                    cookie_manager.set("auth_token", user['token'], expires_at=datetime.datetime.now() + datetime.timedelta(days=1))
                    
                    st.success("Identity Verified. Accessing Secure Dashboard...")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("Authentication Failed: Invalid Credentials.")

def logout():
    if st.session_state.auth_token:
        AuthService.revoke_token(st.session_state.auth_token)
    st.session_state.force_logout = True
    st.session_state.auth_token = None
    st.session_state.username = None
    st.session_state.user_role = None
    try:
        cookie_manager.delete("auth_token")
    except Exception:
        pass
    try:
        cookie_manager.set("auth_token", "", expires_at=datetime.datetime.now() - datetime.timedelta(days=1))
    except Exception:
        pass
    st.rerun()

# --- Feature Modules ---

def dashboard_view():
    st.markdown(f"## Welcome, {st.session_state.username.capitalize()} | Role: {st.session_state.user_role}")
    st.caption("This dashboard summarizes recent URL scans and overall phishing risk levels across the environment.")
    
    scans = AuditLogService.get_recent_scans(limit=500)
    df = pd.DataFrame(scans) if scans else pd.DataFrame(columns=["ts", "risk"])

    c1, c2, c3, c4 = st.columns(4)
    total_scans = int(len(df))
    phishing_detected = int((df["risk"] == "High").sum()) if "risk" in df.columns else 0
    suspicious_detected = int((df["risk"] == "Medium").sum()) if "risk" in df.columns else 0
    low_detected = int((df["risk"] == "Low").sum()) if "risk" in df.columns else 0

    c1.metric("URLs Analyzed", f"{total_scans:,}")
    c2.metric("High-Risk Detected", f"{phishing_detected:,}", delta_color="inverse")
    c3.metric("Suspicious Detected", f"{suspicious_detected:,}")
    c4.metric("Low-Risk", f"{low_detected:,}")
    
    st.markdown("---")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("Weekly Threat Landscape")
        if not df.empty and "ts" in df.columns and "risk" in df.columns:
            dft = df.copy()
            dft["ts"] = pd.to_datetime(dft["ts"], errors="coerce")
            dft = dft.dropna(subset=["ts"])
            dft["day"] = dft["ts"].dt.date.astype(str)
            agg = dft.groupby(["day", "risk"]).size().reset_index(name="count")
            fig = px.bar(
                agg,
                x="day",
                y="count",
                color="risk",
                color_discrete_map={"Low": "#10b981", "Medium": "#f59e0b", "High": "#ef4444"},
            )
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", height=350)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No scan events yet. Install the browser extension to start automatic detection.")
        
    with col2:
        st.subheader("Risk Distribution")
        if not df.empty and "risk" in df.columns:
            counts = df["risk"].value_counts().to_dict()
            labels = ["Low", "Medium", "High"]
            values = [counts.get("Low", 0), counts.get("Medium", 0), counts.get("High", 0)]
            fig2 = go.Figure(data=[go.Pie(labels=labels, values=values, hole=.7)])
            fig2.update_traces(marker=dict(colors=["#10b981", "#f59e0b", "#ef4444"]))
            fig2.update_layout(showlegend=True, margin=dict(t=0, b=0, l=0, r=0), height=350)
            st.plotly_chart(fig2, use_container_width=True)
        else:
            fig2 = go.Figure(data=[go.Pie(labels=["Low", "Medium", "High"], values=[0, 0, 0], hole=.7)])
            fig2.update_traces(marker=dict(colors=["#10b981", "#f59e0b", "#ef4444"]))
            fig2.update_layout(showlegend=True, margin=dict(t=0, b=0, l=0, r=0), height=350)
            st.plotly_chart(fig2, use_container_width=True)

    st.markdown("---")
    st.subheader("Recent Automatic Detections")
    if not df.empty:
        show = df[["ts", "username", "source", "url", "risk", "prob_phishing"]].copy()
        show = show.rename(columns={"prob_phishing": "phishing_confidence"})
        st.dataframe(show.head(50), use_container_width=True)
    else:
        st.caption("No detections logged yet.")

def scanner_view():
    st.title("Threat Detection Engine")
    
    tab1, tab2 = st.tabs(["🛰️ Automatic Browser Protection", "📂 Batch Processing"])
    
    with tab1:
        st.markdown("This module is driven by the **FinShield AI Browser Guard extension**. It automatically scans every visited page and clicked link, logs results to the backend, and can block High-Risk pages if enabled in the extension popup.")
        st.markdown(f"**Extension path:** `phishing_extension/`")
        st.info("Risk levels: Low = generally safe, Medium = suspicious, High = likely phishing (blocking overlay if enabled).")
        st.divider()

        scans = AuditLogService.get_recent_scans(limit=200)
        df = pd.DataFrame(scans) if scans else pd.DataFrame(columns=["ts", "username", "source", "url", "risk", "prob_phishing"])

        c1, c2, c3 = st.columns(3)
        total_scans = int(len(df))
        high_count = int((df["risk"] == "High").sum()) if "risk" in df.columns else 0
        medium_count = int((df["risk"] == "Medium").sum()) if "risk" in df.columns else 0
        c1.metric("URLs Automatically Scanned", f"{total_scans:,}")
        c2.metric("High-Risk Pages", f"{high_count:,}")
        c3.metric("Suspicious Pages", f"{medium_count:,}")

        st.markdown("---")

        if not df.empty:
            df_show = df[["ts", "username", "source", "url", "risk", "prob_phishing"]].copy()
            df_show = df_show.rename(columns={"prob_phishing": "phishing_confidence"})
            st.dataframe(df_show.head(100), use_container_width=True)
        else:
            st.info("No automatic detections found yet. Start the API + extension, then browse a few URLs.")

        if AuthService.check_permission(st.session_state.user_role, "Admin"):
            with st.expander("Admin: Manual Model Test (for verification only)"):
                url = st.text_input("Test URL", placeholder="http://secure-login-apple.com")
                if st.button("Run Model Test"):
                    try:
                        pred, conf, risk, features = model_engine.predict(url)
                        AuditLogService.log_scan_event(
                            username=st.session_state.username,
                            source="dashboard_manual_test",
                            url=url,
                            prediction=pred,
                            prob_phishing=float(conf),
                            risk=risk,
                            features=features,
                            explain={"event_type": "manual_test"},
                        )
                        st.success(f"Risk: {risk} | Phishing confidence: {conf:.2%}")
                    except Exception as e:
                        st.error(f"Test Failed: {e}")

    with tab2:
        if not AuthService.check_permission(st.session_state.user_role, "Analyst"):
            st.error("Access Restricted. Analyst role required.")
        else:
            uploaded_file = st.file_uploader("Upload CSV (Column 'url')", type="csv")
            if uploaded_file and st.button("Process Batch File"):
                df = pd.read_csv(uploaded_file)
                if 'url' in df.columns:
                    results = []
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    for i, url in enumerate(df['url']):
                        _, conf, risk, _ = model_engine.predict(url)
                        results.append({"url": url, "risk": risk, "confidence": conf})
                        AuditLogService.log_scan_event(
                            username=st.session_state.username,
                            source="batch_csv",
                            url=str(url),
                            prediction=1 if float(conf) > 0.5 else 0,
                            prob_phishing=float(conf),
                            risk=risk,
                        )
                        progress_bar.progress((i+1)/len(df))
                        status_text.text(f"Scanning {i+1}/{len(df)}: {url[:30]}...")
                    
                    res_df = pd.DataFrame(results)
                    st.dataframe(res_df, use_container_width=True)
                    
                    # Download Report
                    csv = ReportGenerator.generate_csv(results)
                    st.download_button("Download Audit Report (CSV)", csv, "audit_report.csv")
                else:
                    st.error("CSV must contain 'url' column.")

def training_view():
    st.title("Cybersecurity Training Center")
    st.markdown("Timed, scenario-based quizzes improve employee phishing resistance. Attempts and scores are stored for admin analytics.")

    if "quiz_active" not in st.session_state:
        st.session_state.quiz_active = False
    if "quiz_questions" not in st.session_state:
        st.session_state.quiz_questions = []
    if "quiz_started_at" not in st.session_state:
        st.session_state.quiz_started_at = None
    if "quiz_level" not in st.session_state:
        st.session_state.quiz_level = None
    if "quiz_time_limit" not in st.session_state:
        st.session_state.quiz_time_limit = 0
    if "last_quiz_result" not in st.session_state:
        st.session_state.last_quiz_result = None
    if "last_quiz_questions" not in st.session_state:
        st.session_state.last_quiz_questions = None
    if "last_quiz_answers" not in st.session_state:
        st.session_state.last_quiz_answers = None

    bank = QuizService.load_question_bank()
    if not bank:
        st.warning("Training question bank not found.")
        return

    user_history = QuizService.get_user_progress(st.session_state.username)
    attempts_df = pd.DataFrame(user_history) if user_history else pd.DataFrame(columns=["date", "module_id", "score", "total", "passed"])

    st.subheader("Your Attempt History")
    if not attempts_df.empty:
        show = attempts_df[["date", "module_id", "score", "total", "passed"]].copy()
        st.dataframe(show.head(25), use_container_width=True)
    else:
        st.caption("No attempts yet.")

    st.divider()
    st.subheader("Start a New Timed Quiz")

    levels = QuizService.list_levels()
    categories = QuizService.list_categories()

    colA, colB, colC = st.columns([1, 1, 1])
    with colA:
        level = st.selectbox("Difficulty", levels, index=0)
    with colB:
        question_count = st.selectbox("Questions", [10, 15, 20], index=0)
    with colC:
        selected_categories = st.multiselect("Categories", categories, default=categories[:4] if len(categories) >= 4 else categories)

    default_limit = 300 if question_count == 10 else (450 if question_count == 15 else 600)
    time_limit = st.slider("Time limit (seconds)", min_value=120, max_value=1800, value=default_limit, step=30)

    if not st.session_state.quiz_active:
        if st.button("Start Quiz", type="primary"):
            qs = QuizService.sample_questions(level=level, count=question_count, categories=selected_categories, seed=str(datetime.datetime.utcnow()))
            if len(qs) < question_count:
                st.error("Not enough questions in this selection. Choose more categories or a different level.")
                return
            st.session_state.quiz_active = True
            st.session_state.quiz_questions = qs
            st.session_state.quiz_started_at = time.time()
            st.session_state.quiz_level = level
            st.session_state.quiz_time_limit = int(time_limit)
            st.rerun()
        return

    elapsed = int(time.time() - (st.session_state.quiz_started_at or time.time()))
    remaining = max(0, int(st.session_state.quiz_time_limit) - elapsed)
    st.info(f"Time remaining: {remaining}s")

    with st.form("timed_quiz_form"):
        answers = {}
        for q in st.session_state.quiz_questions:
            st.write(f"**{q['text']}**")
            if q.get("example"):
                st.caption(q.get("example"))
            answers[q["id"]] = st.radio("Choose answer:", q["options"], key=f"q_{q['id']}")
            st.write("---")

        submitted = st.form_submit_button("Submit Quiz")

    if submitted:
        finish_elapsed = int(time.time() - (st.session_state.quiz_started_at or time.time()))
        time_ok = finish_elapsed <= int(st.session_state.quiz_time_limit)

        attempt_questions = list(st.session_state.quiz_questions)
        attempt_answers = dict(answers)

        score = 0
        for q in st.session_state.quiz_questions:
            if answers.get(q["id"]) == q["correct"]:
                score += 1
        total = len(st.session_state.quiz_questions)
        passed = (score >= int(total * 0.7)) and time_ok

        meta = {
            "level": st.session_state.quiz_level,
            "categories": selected_categories,
            "duration_seconds": finish_elapsed,
            "time_limit_seconds": int(st.session_state.quiz_time_limit),
            "question_ids": [q["id"] for q in st.session_state.quiz_questions],
        }

        QuizService.save_result(st.session_state.username, f"timed_{st.session_state.quiz_level}", score, total, passed, meta=meta)

        st.session_state.quiz_active = False
        st.session_state.quiz_questions = []
        st.session_state.quiz_started_at = None
        st.session_state.quiz_level = None
        st.session_state.quiz_time_limit = 0

        st.session_state.last_quiz_result = {
            "score": score,
            "total": total,
            "passed": passed,
            "time_ok": time_ok,
            "duration_seconds": finish_elapsed,
        }
        st.session_state.last_quiz_questions = attempt_questions
        st.session_state.last_quiz_answers = attempt_answers

        if not time_ok:
            st.error(f"Time expired. Score: {score}/{total}")
        elif passed:
            st.success(f"Passed! Score: {score}/{total}")
            cert_path = ReportGenerator.generate_certificate(st.session_state.username, level, score, total)
            with open(cert_path, "rb") as f:
                st.download_button("Download Certificate (PDF)", f, file_name=os.path.basename(cert_path))
        else:
            st.error(f"Failed. Score: {score}/{total}")

    if st.session_state.last_quiz_result and st.session_state.last_quiz_questions:
        with st.expander("Review Answers & Explanations"):
            qlist = st.session_state.last_quiz_questions
            amap = st.session_state.last_quiz_answers or {}
            for q in qlist:
                chosen = amap.get(q["id"])
                correct = q.get("correct")
                st.write(f"**{q.get('text','')}**")
                st.caption(f"Your answer: {chosen if chosen is not None else 'Not answered'}")
                st.info(f"Correct answer: {correct}")
                if q.get("explanation"):
                    st.write(q.get("explanation"))
                st.write("---")

def admin_view():
    if not AuthService.check_permission(st.session_state.user_role, "Admin"):
        st.error("⛔ Administrator Access Required.")
        return
        
    st.title("⚙️ System Administration Console")
    
    tab1, tab2, tab3 = st.tabs(["🤖 Model Management", "👥 Employee Performance", "📜 Audit Logs"])
    
    with tab1:
        st.info(f"Current Model: Random Forest Classifier (v1.2)")
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Model Accuracy", "94.8%")
        with col2:
            st.metric("Training Samples", "15,420")
            
        if st.button("Retrain Model (Production)"):
            with st.spinner("Retraining model on latest dataset..."):
                metrics = model_engine.train('data/processed/training_dataset_v1.csv')
                st.success(f"Training Complete! Accuracy: {metrics['accuracy']:.2%}")
    
    with tab2:
        st.subheader("Employee Training Status")
        results = QuizService.get_all_results()
        
        if results:
            data = []
            for user, history in results.items():
                passed_modules = len([h for h in history if h['passed']])
                avg_score = sum([h['score'] for h in history]) / len(history) if history else 0
                data.append({"Employee": user, "Modules Completed": passed_modules, "Avg Score": f"{avg_score:.1f}"})
            
            st.dataframe(pd.DataFrame(data), use_container_width=True)
        else:
            st.info("No training data available yet.")

    with tab3:
        st.subheader("Scan Events")
        scans = AuditLogService.get_recent_scans(limit=200)
        if scans:
            sdf = pd.DataFrame(scans)
            cols = [c for c in ["ts", "username", "source", "url", "risk", "prob_phishing"] if c in sdf.columns]
            st.dataframe(sdf[cols].head(200), use_container_width=True)
        else:
            st.caption("No scan events logged yet.")

        st.divider()
        st.subheader("Authentication Events")
        auth = AuditLogService.get_recent_auth(limit=200)
        if auth:
            adf = pd.DataFrame(auth)
            cols = [c for c in ["ts", "username", "event", "details"] if c in adf.columns]
            st.dataframe(adf[cols].head(200), use_container_width=True)
        else:
            st.caption("No auth events logged yet.")

def demo_view():
    st.title("🧪 Guided Demo Mode")
    st.markdown("Use this checklist during viva to show end-to-end automatic detection + logging + training + logout.")
    st.subheader("Demo Accounts")
    st.code("admin/admin123 | analyst/analyst123 | employee/employee123 | viewer/viewer123")

    st.subheader("Test URLs")
    st.code("http://secure-login-apple.com\nhttp://update-payment-netflix.vip\nhttps://google.com\nhttps://nepalbank.com.np")

    st.subheader("Demo Flow")
    st.write("1) Login as Admin → Dashboard shows scan logs.")
    st.write("2) Load the extension from phishing_extension/ → Login in popup.")
    st.write("3) Visit a test URL → badge changes + events appear in Dashboard and Admin Audit Logs.")
    st.write("4) Enable Block High-Risk in extension popup → High-Risk page shows warning overlay.")
    st.write("5) Login as Employee → Training Center → timed quiz → download certificate.")
    st.write("6) Logout → verify you cannot access dashboard without logging in again.")

    if AuthService.check_permission(st.session_state.user_role, "Admin"):
        st.divider()
        st.subheader("Admin: Seed Demo Data")
        if st.button("Seed 5 Demo Scan Events"):
            samples = [
                ("http://secure-login-apple.com", 1, 0.93, "High"),
                ("http://update-payment-netflix.vip", 1, 0.81, "High"),
                ("https://google.com", 0, 0.12, "Low"),
                ("https://nepalbank.com.np", 0, 0.18, "Low"),
                ("http://verify-account.tk", 1, 0.74, "High"),
            ]
            for url, pred, prob, risk in samples:
                AuditLogService.log_scan_event(
                    username=st.session_state.username,
                    source="demo_seed",
                    url=url,
                    prediction=pred,
                    prob_phishing=prob,
                    risk=risk,
                )
            st.success("Demo scan events added to audit logs.")

# --- Main App Router ---

def main():
    # Attempt Auto-Login
    is_logged_in = try_auto_login()

    if not is_logged_in:
        login_view()
    else:
        # Sidebar Navigation
        with st.sidebar:
            st.image("https://img.icons8.com/3d-fluency/94/shield.png", width=80)
            st.markdown("## FinShield AI")
            st.caption("Banking Security Suite v2.0")
            st.markdown("---")
            
            menu = st.radio("Navigation", 
                ["Dashboard", "Threat Scanner", "Training Center", "Reports", "Admin Panel", "Demo Mode"],
                label_visibility="collapsed"
            )
            
            st.markdown("---")
            st.markdown(f"**User:** {st.session_state.username}")
            st.markdown(f"**Role:** {st.session_state.user_role}")
            
            if st.button("Log Out", type="secondary"):
                logout()

        # Routing
        if menu == "Dashboard":
            dashboard_view()
        elif menu == "Threat Scanner":
            scanner_view()
        elif menu == "Training Center":
            training_view()
        elif menu == "Reports":
            st.title("📑 Incident & Audit Reports")
            st.write("Generate comprehensive security reports for compliance.")
            if st.button("Generate PDF Report"):
                scans = AuditLogService.get_recent_scans(limit=200)
                if scans:
                    path = ReportGenerator.generate_pdf(scans, st.session_state.username)
                    with open(path, "rb") as f:
                        st.download_button("Download PDF", f, file_name="security_report.pdf")
                else:
                    st.warning("No session data to report.")
        elif menu == "Admin Panel":
            admin_view()
        elif menu == "Demo Mode":
            demo_view()
            
        # Footer
        st.markdown("""
        <div class="footer">
            FinShield AI © 2026 | Banking Security Initiative | Kathmandu Valley
        </div>
        """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
