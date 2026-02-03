# model.py - ML Model Integration for Phishing Detection
import joblib
import os
import numpy as np
from scipy.sparse import hstack, csr_matrix
from step2_features import build_step2_features

class PhishingDetectorML:
    """
    ML-based Phishing Detector using SVM + TF-IDF + Rule-based features
    """
    
    def __init__(self, models_dir: str = "models"):
        """
        Initialize the detector by loading trained models
        
        Args:
            models_dir: Directory containing the trained models
        """
        self.models_dir = models_dir
        self.svm_model = None
        self.vectorizer = None
        self.scaler = None
        self.is_loaded = False
        
        # Try to load models
        self._load_models()
    
    def _load_models(self):
        """Load ML model (SGD or SVM), TF-IDF vectorizer, and scaler"""
        try:
            # Try SGD model first (faster), fallback to SVM
            sgd_path = os.path.join(self.models_dir, "sgd_model.pkl")
            svm_path = os.path.join(self.models_dir, "svm_model.pkl")
            
            if os.path.exists(sgd_path):
                model_path = sgd_path
            elif os.path.exists(svm_path):
                model_path = svm_path
            else:
                model_path = None
            
            vectorizer_path = os.path.join(self.models_dir, "tfidf_vectorizer.pkl")
            scaler_path = os.path.join(self.models_dir, "scaler.pkl")
            
            # Check if files exist
            if model_path is None or not all(os.path.exists(p) for p in [vectorizer_path, scaler_path]):
                print("⚠️  WARNING: ML models not found. Please run train_model_fast.py first.")
                print(f"   Looking in: {os.path.abspath(self.models_dir)}")
                self.is_loaded = False
                return
            
            # Load models
            self.svm_model = joblib.load(model_path)
            self.vectorizer = joblib.load(vectorizer_path)
            self.scaler = joblib.load(scaler_path)
            
            self.is_loaded = True
            model_type = "SGD" if "sgd" in model_path else "SVM"
            print(f"✅ ML models loaded successfully! (Using {model_type})")
            
        except Exception as e:
            print(f"❌ Error loading models: {e}")
            self.is_loaded = False
    
    def _prepare_features(self, email_data: dict):
        """
        Prepare combined features (TF-IDF + rule-based) for prediction
        
        Args:
            email_data: Dict with 'subject', 'body', 'sender'
        
        Returns:
            Combined feature matrix
        """
        subject = email_data.get('subject', '')
        body = email_data.get('body', '')
        sender = email_data.get('sender', '')
        
        # Combine subject and body for TF-IDF
        full_text = f"{subject} {body}"
        
        # 1. TF-IDF features
        tfidf_features = self.vectorizer.transform([full_text])
        
        # 2. Rule-based features
        rule_features_dict = build_step2_features(
            body=body,
            subject=subject,
            sender=sender
        )
        
        # Convert to ordered array (same order as training)
        rule_features = np.array([[
            rule_features_dict['link_count'],
            rule_features_dict['suspicious_word_count'],
            rule_features_dict['email_length'],
            rule_features_dict['is_trusted_domain'],
            rule_features_dict['suspicious_domain_pattern'],
            rule_features_dict['suspicious_special_chars'],
            rule_features_dict['has_excessive_caps'],
            rule_features_dict['has_ip_address_link'],
            rule_features_dict['has_shortened_url'],
            rule_features_dict['has_currency_symbols'],
            rule_features_dict['has_attachment_keywords'],
            rule_features_dict['link_domain_mismatch']
        ]])
        
        # 3. Scale rule-based features
        rule_features_scaled = self.scaler.transform(rule_features)
        
        # 4. Combine TF-IDF + scaled rule features
        rule_features_sparse = csr_matrix(rule_features_scaled)
        combined_features = hstack([tfidf_features, rule_features_sparse])
        
        return combined_features
    
    def predict(self, email_data: dict) -> dict:
        """
        Predict if email is phishing
        
        Args:
            email_data: Dict with keys 'subject', 'body', 'sender'
        
        Returns:
            Dict with prediction results
        """
        if not self.is_loaded:
            # Fallback to rule-based if ML models not loaded
            return {
                "is_phishing": False,
                "confidence": 0.0,
                "method": "models_not_loaded",
                "message": "ML models not trained yet. Please run train_model.py"
            }
        
        try:
            # Prepare features
            features = self._prepare_features(email_data)
            
            # Get prediction and probability
            prediction = self.svm_model.predict(features)[0]
            probabilities = self.svm_model.predict_proba(features)[0]
            
            # Confidence is the probability of the predicted class
            confidence = probabilities[1] if prediction == 1 else probabilities[0]
            
            return {
                "is_phishing": bool(prediction),
                "confidence": float(confidence),
                "method": "ml_classifier",
                "probabilities": {
                    "legitimate": float(probabilities[0]),
                    "phishing": float(probabilities[1])
                }
            }
            
        except Exception as e:
            print(f"❌ Prediction error: {e}")
            return {
                "is_phishing": False,
                "confidence": 0.0,
                "method": "error",
                "message": str(e)
            }


# ==========================================================
# FALLBACK: Rule-Based Detector (Original)
# ==========================================================

class PhishingDetectorStep1:
    """
    Original rule-based detector (fallback if ML not available)
    """
    
    def predict(self, email_data: dict) -> dict:
        """
        Rule-based phishing detection
        
        Args:
            email_data: Dict with 'subject', 'body', 'sender'
        
        Returns:
            Dict with prediction results
        """
        from step2_features import build_step2_features
        
        subject = email_data.get('subject', '')
        body = email_data.get('body', '')
        sender = email_data.get('sender', '')
        
        # Extract features
        features = build_step2_features(body, subject, sender)
        
        # Simple rule-based scoring
        risk_score = 0
        
        # High risk indicators (3 points each)
        if features['has_ip_address_link']:
            risk_score += 3
        if features['link_domain_mismatch']:
            risk_score += 3
        if not features['is_trusted_domain'] and features['suspicious_domain_pattern']:
            risk_score += 3
        
        # Medium risk indicators (2 points each)
        if features['suspicious_word_count'] >= 3:
            risk_score += 2
        if features['link_count'] >= 3:
            risk_score += 2
        if features['has_shortened_url']:
            risk_score += 2
        
        # Low risk indicators (1 point each)
        if features['has_excessive_caps']:
            risk_score += 1
        if features['has_currency_symbols']:
            risk_score += 1
        if features['has_attachment_keywords']:
            risk_score += 1
        if features['suspicious_special_chars'] > 20:
            risk_score += 1
        
        # Decision threshold
        is_phishing = risk_score >= 5
        
        # Convert to confidence (0-1 scale)
        confidence = min(risk_score / 10, 1.0)
        
        return {
            "is_phishing": is_phishing,
            "confidence": confidence,
            "step": "rule_based",
            "risk_score": risk_score
        }