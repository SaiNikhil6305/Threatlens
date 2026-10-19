import pandas as pd
from typing import Tuple
from sklearn.model_selection import train_test_split
from ml.config import ENRON_DATASET_PATH, RANDOM_STATE, TEST_SIZE

def load_text_dataset(filepath=ENRON_DATASET_PATH) -> pd.DataFrame:
    """Loads and validates text dataset."""
    if not filepath.exists():
        raise FileNotFoundError(f"Dataset not found at {filepath}. Run scripts/prepare_datasets.py first.")
    df = pd.read_csv(filepath)
    df = df.dropna(subset=["text", "label"])
    df["text"] = df["text"].astype(str).str.strip()
    df = df[df["text"].str.len() > 10]
    return df

def get_train_val_test_splits(
    filepath=ENRON_DATASET_PATH, test_size=TEST_SIZE, val_size=0.10
) -> Tuple[pd.Series, pd.Series, pd.Series, pd.Series, pd.Series, pd.Series]:
    """
    Returns (X_train, X_val, X_test, y_train, y_val, y_test)
    using stratified splitting to preserve class balance.
    """
    df = load_text_dataset(filepath)
    X = df["text"]
    y = df["label"]

    # First split off test set
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=test_size, random_state=RANDOM_STATE, stratify=y
    )

    # Next split train into train and validation
    val_relative = val_size / (1.0 - test_size)
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=val_relative, random_state=RANDOM_STATE, stratify=y_train_val
    )

    return X_train, X_val, X_test, y_train, y_val, y_test
