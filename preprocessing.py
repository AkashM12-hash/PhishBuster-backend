# preprocessing.py - Dataset Loading and Preprocessing
import pandas as pd
import re
from typing import Tuple
import os

# ==========================================================
# TEXT CLEANING FUNCTIONS
# ==========================================================

def clean_text(text):
    """Clean email text - remove extra spaces, newlines, etc."""
    if not isinstance(text, str):
        return ""
    
    # Convert to lowercase
    text = text.lower()
    
    # Remove extra whitespace
    text = re.sub(r'\s+', ' ', text)
    
    # Remove special email artifacts
    text = re.sub(r'[\r\n\t]', ' ', text)
    
    return text.strip()

def extract_email_content(text):
    """Extract meaningful content from raw email text"""
    if not isinstance(text, str):
        return ""
    
    # Remove email headers (From:, To:, Subject:, etc.)
    text = re.sub(r'^(From|To|Subject|Date|Cc|Bcc):.*?$', '', text, flags=re.MULTILINE)
    
    # Remove email signatures
    text = re.sub(r'--\s*$.*', '', text, flags=re.DOTALL)
    
    # Remove excessive newlines
    text = re.sub(r'\n{3,}', '\n\n', text)
    
    return text.strip()

# ==========================================================
# DATASET LOADING FUNCTIONS
# ==========================================================

def load_enron_dataset(filepath: str, sample_size: int = 50000) -> pd.DataFrame:
    """
    Load Enron legitimate emails
    
    Args:
        filepath: Path to Enron.csv
        sample_size: Number of emails to sample (default 50000)
    
    Returns:
        DataFrame with columns: text, label
    """
    print(f"📧 Loading Enron dataset from: {filepath}")
    
    try:
        # Try different encodings
        try:
            df = pd.read_csv(filepath, encoding='utf-8')
        except:
            df = pd.read_csv(filepath, encoding='latin-1')
        
        print(f"   Original size: {len(df)} emails")
        
        # Common Enron dataset column names
        text_column = None
        for col in ['message', 'body', 'text', 'content', 'Message']:
            if col in df.columns:
                text_column = col
                break
        
        if text_column is None:
            # If no text column found, use the last column
            text_column = df.columns[-1]
            print(f"   ⚠️  Using column '{text_column}' as text content")
        
        # Create standardized dataframe
        df_clean = pd.DataFrame({
            'text': df[text_column].astype(str),
            'label': 0  # 0 = legitimate
        })
        
        # Clean text
        df_clean['text'] = df_clean['text'].apply(clean_text)
        
        # Remove empty or very short emails
        df_clean = df_clean[df_clean['text'].str.len() > 20]
        
        # Sample if dataset is too large
        if len(df_clean) > sample_size:
            df_clean = df_clean.sample(n=sample_size, random_state=42)
            print(f"   Sampled to: {len(df_clean)} emails")
        
        print(f"   ✅ Loaded {len(df_clean)} legitimate emails")
        return df_clean
        
    except Exception as e:
        print(f"   ❌ Error loading Enron dataset: {e}")
        return pd.DataFrame(columns=['text', 'label'])

def load_nazario_dataset(filepath: str) -> pd.DataFrame:
    """
    Load Nazario phishing corpus
    
    Args:
        filepath: Path to Nazario.csv
    
    Returns:
        DataFrame with columns: text, label
    """
    print(f"🎣 Loading Nazario phishing dataset from: {filepath}")
    
    try:
        # Try different encodings
        try:
            df = pd.read_csv(filepath, encoding='utf-8')
        except:
            df = pd.read_csv(filepath, encoding='latin-1')
        
        print(f"   Original size: {len(df)} emails")
        
        # Find text column
        text_column = None
        for col in ['message', 'body', 'text', 'content', 'email']:
            if col in df.columns:
                text_column = col
                break
        
        if text_column is None:
            text_column = df.columns[-1]
            print(f"   ⚠️  Using column '{text_column}' as text content")
        
        # Create standardized dataframe
        df_clean = pd.DataFrame({
            'text': df[text_column].astype(str),
            'label': 1  # 1 = phishing
        })
        
        # Clean text
        df_clean['text'] = df_clean['text'].apply(clean_text)
        
        # Remove empty or very short emails
        df_clean = df_clean[df_clean['text'].str.len() > 20]
        
        print(f"   ✅ Loaded {len(df_clean)} phishing emails")
        return df_clean
        
    except Exception as e:
        print(f"   ❌ Error loading Nazario dataset: {e}")
        return pd.DataFrame(columns=['text', 'label'])

def load_phishing_email_dataset(filepath: str) -> pd.DataFrame:
    """
    Load additional phishing_email.csv dataset
    
    Args:
        filepath: Path to phishing_email.csv
    
    Returns:
        DataFrame with columns: text, label
    """
    print(f"📧 Loading phishing_email dataset from: {filepath}")
    
    try:
        # Try different encodings
        try:
            df = pd.read_csv(filepath, encoding='utf-8')
        except:
            df = pd.read_csv(filepath, encoding='latin-1')
        
        print(f"   Original size: {len(df)} emails")
        print(f"   Columns found: {list(df.columns)}")
        
        # This dataset might already have labels
        label_column = None
        text_column = None
        
        # Find label column
        for col in ['label', 'class', 'type', 'is_phishing', 'Email Type']:
            if col in df.columns:
                label_column = col
                break
        
        # Find text column
        for col in ['message', 'body', 'text', 'content', 'email', 'Email Text']:
            if col in df.columns:
                text_column = col
                break
        
        if text_column is None:
            # Use first or last column
            text_column = df.columns[0] if len(df.columns) > 1 else df.columns[-1]
            print(f"   ⚠️  Using column '{text_column}' as text content")
        
        # Create standardized dataframe
        if label_column:
            # Map labels to 0/1
            df_clean = pd.DataFrame({
                'text': df[text_column].astype(str),
                'label': df[label_column]
            })
            
            # Standardize labels
            label_mapping = {
                'Phishing Email': 1, 'Safe Email': 0,
                'phishing': 1, 'safe': 1, 'legitimate': 0, 'ham': 0,
                'spam': 1, 1: 1, 0: 0, '1': 1, '0': 0
            }
            
            df_clean['label'] = df_clean['label'].map(
                lambda x: label_mapping.get(x, 1)  # Default to phishing if unknown
            )
        else:
            # Assume all are phishing
            df_clean = pd.DataFrame({
                'text': df[text_column].astype(str),
                'label': 1  # Assume phishing
            })
        
        # Clean text
        df_clean['text'] = df_clean['text'].apply(clean_text)
        
        # Remove empty or very short emails
        df_clean = df_clean[df_clean['text'].str.len() > 20]
        
        phishing_count = df_clean['label'].sum()
        legitimate_count = len(df_clean) - phishing_count
        
        print(f"   ✅ Loaded {len(df_clean)} emails")
        print(f"      - Phishing: {phishing_count}")
        print(f"      - Legitimate: {legitimate_count}")
        
        return df_clean
        
    except Exception as e:
        print(f"   ❌ Error loading phishing_email dataset: {e}")
        return pd.DataFrame(columns=['text', 'label'])

# ==========================================================
# MAIN PREPROCESSING FUNCTION
# ==========================================================

def load_and_prepare_datasets(
    enron_path: str,
    nazario_path: str,
    phishing_email_path: str,
    enron_sample_size: int = 50000
) -> Tuple[pd.DataFrame, dict]:
    """
    Load all datasets and combine them
    
    Args:
        enron_path: Path to Enron.csv
        nazario_path: Path to Nazario.csv
        phishing_email_path: Path to phishing_email.csv
        enron_sample_size: Number of Enron emails to use
    
    Returns:
        Combined DataFrame and statistics dictionary
    """
    print("="*60)
    print("🚀 STARTING DATASET LOADING")
    print("="*60)
    
    # Load individual datasets
    df_enron = load_enron_dataset(enron_path, enron_sample_size)
    df_nazario = load_nazario_dataset(nazario_path)
    df_phishing = load_phishing_email_dataset(phishing_email_path)
    
    # Combine all datasets
    print("\n" + "="*60)
    print("🔗 COMBINING DATASETS")
    print("="*60)
    
    df_combined = pd.concat([df_enron, df_nazario, df_phishing], ignore_index=True)
    
    # Remove duplicates
    initial_size = len(df_combined)
    df_combined = df_combined.drop_duplicates(subset=['text'])
    duplicates_removed = initial_size - len(df_combined)
    
    # Shuffle the dataset
    df_combined = df_combined.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Calculate statistics
    stats = {
        'total_emails': len(df_combined),
        'phishing_emails': int(df_combined['label'].sum()),
        'legitimate_emails': int((df_combined['label'] == 0).sum()),
        'duplicates_removed': duplicates_removed,
        'datasets_loaded': 3
    }
    
    stats['balance_ratio'] = stats['phishing_emails'] / stats['legitimate_emails']
    
    print(f"\n📊 FINAL DATASET STATISTICS:")
    print(f"   Total emails: {stats['total_emails']:,}")
    print(f"   Phishing: {stats['phishing_emails']:,} ({stats['phishing_emails']/stats['total_emails']*100:.1f}%)")
    print(f"   Legitimate: {stats['legitimate_emails']:,} ({stats['legitimate_emails']/stats['total_emails']*100:.1f}%)")
    print(f"   Duplicates removed: {stats['duplicates_removed']:,}")
    print(f"   Balance ratio: {stats['balance_ratio']:.2f}")
    
    return df_combined, stats

# ==========================================================
# SAVE PROCESSED DATASET
# ==========================================================

def save_processed_dataset(df: pd.DataFrame, output_path: str):
    """Save processed dataset to CSV"""
    df.to_csv(output_path, index=False, encoding='utf-8')
    print(f"\n💾 Dataset saved to: {output_path}")

# ==========================================================
# EXAMPLE USAGE
# ==========================================================

if __name__ == "__main__":
    # Example paths (update these to your actual paths)
    ENRON_PATH = r"D:\phishing_Detection\backend\Enron.csv"
    NAZARIO_PATH = r"D:\phishing_Detection\backend\Nazario.csv"
    PHISHING_PATH = r"D:\phishing_Detection\backend\phishing_email.csv"
    OUTPUT_PATH = r"D:\phishing_Detection\backend\processed_dataset.csv"
    
    # Load and prepare
    df, stats = load_and_prepare_datasets(
        enron_path=ENRON_PATH,
        nazario_path=NAZARIO_PATH,
        phishing_email_path=PHISHING_PATH,
        enron_sample_size=50000
    )
    
    # Save processed dataset
    save_processed_dataset(df, OUTPUT_PATH)
    
    print("\n✅ Preprocessing complete!")