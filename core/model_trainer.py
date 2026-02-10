import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score, f1_score
import joblib
import os
import sys

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.url_feature_extractor import FeatureExtractor

class ModelEngine:
    """
    Core Machine Learning Engine for Phishing Detection.
    Handles data preprocessing, training, evaluation, and persistence.
    """
    
    def __init__(self, model_path='models/phishing_model.pkl', feature_cols_path='models/feature_cols.pkl'):
        self.model_path = model_path
        self.feature_cols_path = feature_cols_path
        self.model = None
        self.feature_columns = None
        self.load_model()

    def load_model(self):
        """Loads the trained model from disk if available."""
        if os.path.exists(self.model_path) and os.path.exists(self.feature_cols_path):
            self.model = joblib.load(self.model_path)
            self.feature_columns = joblib.load(self.feature_cols_path)
            return True
        return False

    def train(self, data_path, save=True):
        """
        Trains the Random Forest model on the provided dataset.
        """
        if not os.path.exists(data_path):
            print(f"Dataset not found at {data_path}. Creating synthetic data.")
            self._create_synthetic_data(data_path)
            
        print("🔄 Loading dataset...")
        raw_df = pd.read_csv(data_path)
        
        # Feature Extraction
        print("⚙️ Extracting features (this may take a moment)...")
        features_list = []
        labels = []
        
        for idx, row in raw_df.iterrows():
            url = row.get('url')
            label = row.get('label')
            
            if url and label is not None:
                feats = FeatureExtractor.extract(url)
                if feats:
                    features_list.append(feats)
                    labels.append(label)
        
        df = pd.DataFrame(features_list)
        df['label'] = labels
        
        # Preprocessing
        X = df.drop(columns=['label'])
        y = df['label']
        self.feature_columns = X.columns.tolist()
        
        # Splitting
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        
        # Training
        print("🚀 Training Random Forest Classifier...")
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=5,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(X_train, y_train)
        
        # Evaluation
        y_pred = self.model.predict(X_test)
        metrics = {
            "accuracy": accuracy_score(y_test, y_pred),
            "precision": precision_score(y_test, y_pred),
            "recall": recall_score(y_test, y_pred),
            "f1": f1_score(y_test, y_pred)
        }
        
        print(f"✅ Training Complete. Metrics: {metrics}")
        
        if save:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            joblib.dump(self.model, self.model_path)
            joblib.dump(self.feature_columns, self.feature_cols_path)
            print(f"💾 Model saved to {self.model_path}")
            
        return metrics

    def predict(self, url):
        """
        Predicts whether a URL is phishing or legitimate.
        Returns: (prediction_label, confidence_score, risk_level, details)
        """
        if not self.model:
            raise ValueError("Model not trained or loaded.")
            
        features = FeatureExtractor.extract(url)
        if not features:
            return None
            
        df = pd.DataFrame([features])
        # Ensure correct column order, filling missing with 0
        df = df.reindex(columns=self.feature_columns, fill_value=0)
        
        prob_phishing = self.model.predict_proba(df)[0][1]
        prediction = 1 if prob_phishing > 0.5 else 0
        
        if prob_phishing < 0.3:
            risk = "Low"
        elif prob_phishing < 0.75:
            risk = "Medium"
        else:
            risk = "High"
        
        if risk == "Medium":
            benign_score = 0
            if features.get("is_https") == 1:
                benign_score += 1
            if features.get("suspicious_tld") == 0:
                benign_score += 1
            if features.get("sensitive_words_count", 0) == 0:
                benign_score += 1
            if features.get("brand_impersonation", 0) == 0:
                benign_score += 1
            if features.get("ip_in_url", 0) == 0:
                benign_score += 1

            suspicious_score = 0
            if features.get("suspicious_tld") == 1:
                suspicious_score += 1
            if features.get("sensitive_words_count", 0) >= 1:
                suspicious_score += 1
            if features.get("brand_impersonation", 0) == 1:
                suspicious_score += 1
            if features.get("ip_in_url", 0) == 1:
                suspicious_score += 1
            if features.get("shortening_service", 0) == 1:
                suspicious_score += 1

            if prob_phishing < 0.6 and benign_score >= 4:
                risk = "Low"
            elif prob_phishing >= 0.55 and suspicious_score >= 2:
                risk = "High"
            
        return prediction, prob_phishing, risk, features

    def _create_synthetic_data(self, path):
        """Creates a dummy dataset if none exists."""
        data = {
            "url": [
                "http://google.com", "https://facebook.com", "https://nepalbank.com.np", "https://github.com", # Legit
                "http://secure-login-apple.com", "http://update-payment-netflix.vip", "http://free-bonus-cash.xyz", "http://verify-account.tk" # Phish
            ],
            "label": [0, 0, 0, 0, 1, 1, 1, 1]
        }
        os.makedirs(os.path.dirname(path), exist_ok=True)
        pd.DataFrame(data).to_csv(path, index=False)
