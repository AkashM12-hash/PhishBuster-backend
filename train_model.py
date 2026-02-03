# train_model_fast.py - FAST Training with SGDClassifier
# This completes in 5-10 minutes instead of 18+ hours!

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier  # MUCH FASTER than SVM!
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import os
from datetime import datetime
import time

# Import our preprocessing and feature extraction
from preprocessing import load_and_prepare_datasets
from step2_features import build_step2_features

# ==========================================================
# OPTIMIZED CONFIGURATION
# ==========================================================

CONFIG = {
    # Dataset paths
    'enron_path': r"D:\phishing_Detection\backend\Enron.csv",
    'nazario_path': r"D:\phishing_Detection\backend\Nazario.csv",
    'phishing_path': r"D:\phishing_Detection\backend\phishing_email.csv",
    
    # Output paths
    'models_dir': r"D:\phishing_Detection\backend\models",
    'model_filename': 'sgd_model.pkl',  # SGD instead of SVM
    'vectorizer_filename': 'tfidf_vectorizer.pkl',
    'scaler_filename': 'scaler.pkl',
    
    # Training parameters (OPTIMIZED FOR SPEED)
    'max_train_samples': 50000,  # Limit total training samples for speed
    'enron_sample_size': 25000,  # Reduce Enron samples
    'test_size': 0.2,
    'random_state': 42,
    
    # TF-IDF parameters (OPTIMIZED)
    'max_features': 3000,  # Reduced from 5000 for speed
    'min_df': 3,           # Slightly higher to reduce features
    'max_df': 0.8,
    'ngram_range': (1, 2),
    
    # SGDClassifier parameters (FAST!)
    'loss': 'log_loss',           # Logistic regression (gives probabilities)
    'penalty': 'l2',              # L2 regularization
    'alpha': 0.0001,              # Regularization strength
    'max_iter': 1000,             # Maximum iterations
    'class_weight': 'balanced',   # Handle imbalance
    'n_jobs': -1                  # Use all CPU cores
}

# ==========================================================
# FAST FEATURE EXTRACTION (with progress bar)
# ==========================================================

def extract_rule_features_batch_fast(df: pd.DataFrame) -> np.ndarray:
    """
    Extract rule-based features with better progress indication
    """
    print("\n🔧 Extracting rule-based features...")
    
    features_list = []
    total = len(df)
    start_time = time.time()
    
    for idx, row in df.iterrows():
        features = build_step2_features(
            body=row['text'],
            subject="",
            sender=""
        )
        
        feature_vector = [
            features['link_count'],
            features['suspicious_word_count'],
            features['email_length'],
            features['is_trusted_domain'],
            features['suspicious_domain_pattern'],
            features['suspicious_special_chars'],
            features['has_excessive_caps'],
            features['has_ip_address_link'],
            features['has_shortened_url'],
            features['has_currency_symbols'],
            features['has_attachment_keywords'],
            features['link_domain_mismatch']
        ]
        
        features_list.append(feature_vector)
        
        # Progress with ETA
        if (idx + 1) % 2500 == 0:
            elapsed = time.time() - start_time
            progress = (idx + 1) / total
            eta = (elapsed / progress - elapsed) if progress > 0 else 0
            print(f"   [{idx + 1:,}/{total:,}] - {progress*100:.1f}% - ETA: {eta/60:.1f} min")
    
    elapsed = time.time() - start_time
    print(f"   ✅ Extracted {len(df):,} features in {elapsed/60:.1f} minutes")
    
    return np.array(features_list)

# ==========================================================
# COMBINE FEATURES
# ==========================================================

def combine_features(tfidf_features, rule_features):
    """Combine TF-IDF + rule-based features"""
    from scipy.sparse import hstack, csr_matrix
    
    rule_features_sparse = csr_matrix(rule_features)
    combined = hstack([tfidf_features, rule_features_sparse])
    
    print(f"\n🔗 Combined Features:")
    print(f"   TF-IDF: {tfidf_features.shape[1]}, Rule-based: {rule_features.shape[1]}")
    print(f"   Total: {combined.shape[1]}")
    
    return combined

# ==========================================================
# MAIN TRAINING FUNCTION
# ==========================================================

def train_phishing_detector_fast():
    """
    FAST training pipeline using SGDClassifier
    Completes in 5-10 minutes!
    """
    total_start = time.time()
    
    print("="*70)
    print(" ⚡ FAST PHISHING DETECTOR TRAINING (SGDClassifier)")
    print("="*70)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("Expected time: 5-10 minutes")
    
    # ====== STEP 1: Load Datasets ======
    print("\n" + "="*70)
    print("STEP 1: LOADING DATASETS")
    print("="*70)
    
    step_start = time.time()
    
    df, stats = load_and_prepare_datasets(
        enron_path=CONFIG['enron_path'],
        nazario_path=CONFIG['nazario_path'],
        phishing_email_path=CONFIG['phishing_path'],
        enron_sample_size=CONFIG['enron_sample_size']
    )
    
    if len(df) == 0:
        print("\n❌ ERROR: No data loaded!")
        return
    
    # LIMIT TOTAL SAMPLES FOR SPEED
    if len(df) > CONFIG['max_train_samples']:
        print(f"\n⚡ Reducing dataset to {CONFIG['max_train_samples']:,} samples for faster training...")
        df = df.sample(n=CONFIG['max_train_samples'], random_state=42)
        print(f"   New size: {len(df):,} emails")
    
    print(f"⏱️  Step 1 completed in {(time.time()-step_start)/60:.1f} minutes")
    
    # ====== STEP 2: Split Data ======
    print("\n" + "="*70)
    print("STEP 2: SPLITTING DATA")
    print("="*70)
    
    X_text = df['text'].values
    y = df['label'].values
    
    X_text_train, X_text_test, y_train, y_test = train_test_split(
        X_text, y,
        test_size=CONFIG['test_size'],
        random_state=CONFIG['random_state'],
        stratify=y
    )
    
    print(f"   Training: {len(X_text_train):,} | Test: {len(X_text_test):,}")
    print(f"   Phishing in train: {y_train.sum():,} ({y_train.sum()/len(y_train)*100:.1f}%)")
    
    # ====== STEP 3: TF-IDF Vectorization ======
    print("\n" + "="*70)
    print("STEP 3: TF-IDF VECTORIZATION")
    print("="*70)
    
    step_start = time.time()
    
    vectorizer = TfidfVectorizer(
        max_features=CONFIG['max_features'],
        min_df=CONFIG['min_df'],
        max_df=CONFIG['max_df'],
        ngram_range=CONFIG['ngram_range'],
        strip_accents='unicode',
        lowercase=True,
        stop_words='english'
    )
    
    print("   Fitting TF-IDF...")
    X_tfidf_train = vectorizer.fit_transform(X_text_train)
    X_tfidf_test = vectorizer.transform(X_text_test)
    
    print(f"   ✅ Vocabulary: {len(vectorizer.vocabulary_):,} words")
    print(f"⏱️  Step 3 completed in {(time.time()-step_start)/60:.1f} minutes")
    
    # ====== STEP 4: Extract Rule Features ======
    print("\n" + "="*70)
    print("STEP 4: EXTRACTING RULE-BASED FEATURES")
    print("="*70)
    
    step_start = time.time()
    
    df_train = pd.DataFrame({'text': X_text_train})
    df_test = pd.DataFrame({'text': X_text_test})
    
    print("📊 Training set:")
    X_rule_train = extract_rule_features_batch_fast(df_train)
    
    print("\n📊 Test set:")
    X_rule_test = extract_rule_features_batch_fast(df_test)
    
    print(f"⏱️  Step 4 completed in {(time.time()-step_start)/60:.1f} minutes")
    
    # ====== STEP 5: Scale Features ======
    print("\n" + "="*70)
    print("STEP 5: SCALING FEATURES")
    print("="*70)
    
    scaler = StandardScaler()
    X_rule_train_scaled = scaler.fit_transform(X_rule_train)
    X_rule_test_scaled = scaler.transform(X_rule_test)
    print("   ✅ Scaled")
    
    # ====== STEP 6: Combine Features ======
    print("\n" + "="*70)
    print("STEP 6: COMBINING FEATURES")
    print("="*70)
    
    X_train_combined = combine_features(X_tfidf_train, X_rule_train_scaled)
    X_test_combined = combine_features(X_tfidf_test, X_rule_test_scaled)
    
    # ====== STEP 7: Train SGD Model (FAST!) ======
    print("\n" + "="*70)
    print("STEP 7: TRAINING SGD MODEL (FAST!)")
    print("="*70)
    
    step_start = time.time()
    
    print(f"   Loss: {CONFIG['loss']}")
    print(f"   Penalty: {CONFIG['penalty']}")
    print(f"   Max iterations: {CONFIG['max_iter']}")
    print(f"   Using all CPU cores")
    print("\n   ⚡ Training starting... (should take 1-2 minutes)")
    
    # SGDClassifier is MUCH faster than SVM!
    sgd_model = SGDClassifier(
        loss=CONFIG['loss'],
        penalty=CONFIG['penalty'],
        alpha=CONFIG['alpha'],
        max_iter=CONFIG['max_iter'],
        class_weight=CONFIG['class_weight'],
        random_state=CONFIG['random_state'],
        n_jobs=CONFIG['n_jobs'],
        verbose=1
    )
    
    sgd_model.fit(X_train_combined, y_train)
    
    train_time = time.time() - step_start
    print(f"\n   ✅ Training complete in {train_time/60:.1f} minutes!")
    
    # ====== STEP 8: Evaluate ======
    print("\n" + "="*70)
    print("STEP 8: MODEL EVALUATION")
    print("="*70)
    
    y_pred_train = sgd_model.predict(X_train_combined)
    y_pred_test = sgd_model.predict(X_test_combined)
    
    train_accuracy = accuracy_score(y_train, y_pred_train)
    test_accuracy = accuracy_score(y_test, y_pred_test)
    
    print(f"\n📊 ACCURACY SCORES:")
    print(f"   Training: {train_accuracy*100:.2f}%")
    print(f"   Test: {test_accuracy*100:.2f}%")
    
    print(f"\n📈 CLASSIFICATION REPORT:")
    print(classification_report(y_test, y_pred_test, 
                                target_names=['Legitimate', 'Phishing'],
                                digits=4))
    
    cm = confusion_matrix(y_test, y_pred_test)
    print(f"🎯 CONFUSION MATRIX:")
    print(f"                  Predicted")
    print(f"               Legit    Phish")
    print(f"   Actual Legit {cm[0][0]:6d}  {cm[0][1]:6d}")
    print(f"   Actual Phish {cm[1][0]:6d}  {cm[1][1]:6d}")
    
    # ====== STEP 9: Save Models ======
    print("\n" + "="*70)
    print("STEP 9: SAVING MODELS")
    print("="*70)
    
    os.makedirs(CONFIG['models_dir'], exist_ok=True)
    
    model_path = os.path.join(CONFIG['models_dir'], CONFIG['model_filename'])
    vectorizer_path = os.path.join(CONFIG['models_dir'], CONFIG['vectorizer_filename'])
    scaler_path = os.path.join(CONFIG['models_dir'], CONFIG['scaler_filename'])
    
    joblib.dump(sgd_model, model_path)
    joblib.dump(vectorizer, vectorizer_path)
    joblib.dump(scaler, scaler_path)
    
    print(f"   ✅ SGD model → {model_path}")
    print(f"   ✅ Vectorizer → {vectorizer_path}")
    print(f"   ✅ Scaler → {scaler_path}")
    
    # Save training info
    training_info = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'model_type': 'SGDClassifier',
        'total_emails': len(df),
        'train_size': len(X_text_train),
        'test_size': len(X_text_test),
        'train_accuracy': float(train_accuracy),
        'test_accuracy': float(test_accuracy),
        'training_time_minutes': float((time.time() - total_start) / 60),
        'tfidf_features': X_tfidf_train.shape[1],
        'rule_features': 12,
        'total_features': X_train_combined.shape[1],
        'config': CONFIG
    }
    
    import json
    info_path = os.path.join(CONFIG['models_dir'], 'training_info.json')
    with open(info_path, 'w') as f:
        json.dump(training_info, f, indent=2)
    
    print(f"   ✅ Training info → {info_path}")
    
    # ====== DONE ======
    total_time = (time.time() - total_start) / 60
    
    print("\n" + "="*70)
    print("✅ TRAINING COMPLETE!")
    print("="*70)
    print(f"Total time: {total_time:.1f} minutes")
    print(f"Test Accuracy: {test_accuracy*100:.2f}%")
    print(f"\n🎯 Model saved to: {CONFIG['models_dir']}")
    print("\n⚡ Ready to use in main.py!")
    print("\nNote: Update model.py to load 'sgd_model.pkl' instead of 'svm_model.pkl'")

if __name__ == "__main__":
    train_phishing_detector_fast()