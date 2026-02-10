import os
import subprocess
import sys
import time

def check_dependencies():
    print("🔍 [System Check] Verifying dependencies...")
    try:
        import streamlit
        import pandas
        import sklearn
        import plotly
        import fpdf
        import jwt  # pyjwt
        import tldextract
        import extra_streamlit_components
        import requests
        import fastapi
        import uvicorn
        from dotenv import load_dotenv
        print("✅ Dependencies verified.")
    except ImportError as e:
        print(f"⚠️ Missing dependency: {e.name}")
        print("📦 Installing required packages...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

def ensure_model_exists():
    print("🧠 [AI Core] Checking Model Status...")
    model_path = os.path.join("models", "phishing_model.pkl")
    if not os.path.exists(model_path):
        print("⚙️ Model artifact not found. Initializing training pipeline...")
        # We can import the trainer directly to train
        try:
            sys.path.append(os.path.dirname(__file__))
            from core.model_trainer import ModelEngine
            engine = ModelEngine()
            engine.train('data/processed/training_dataset_v1.csv')
            print("✅ Model training completed successfully.")
        except Exception as e:
            print(f"❌ Critical Error during training: {e}")
            sys.exit(1)
    else:
        print("✅ Trained Model found.")

def run_application():
    print("🚀 [Launcher] Starting FinShield AI Platform...")
    print("👉 Dashboard: http://localhost:8501")
    print("👉 API Docs: http://localhost:8000/docs")
    api_process = None
    try:
        try:
            from dotenv import load_dotenv
            load_dotenv()
        except Exception:
            pass
        api_process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "api.main:app", "--host", "127.0.0.1", "--port", "8000"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(1)
        subprocess.run([sys.executable, "-m", "streamlit", "run", "web/app.py"], check=True)
    except KeyboardInterrupt:
        print("\n🛑 System Shutting Down...")
    finally:
        if api_process and api_process.poll() is None:
            api_process.terminate()
            try:
                api_process.wait(timeout=5)
            except Exception:
                pass

def main():
    print("""
    =======================================================
       🛡️ FinShield AI | Banking Phishing Protection Platform
    =======================================================
    """)
    check_dependencies()
    ensure_model_exists()
    run_application()

if __name__ == "__main__":
    main()
