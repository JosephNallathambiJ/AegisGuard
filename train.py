"""
train.py - Training Pipeline for Vulnerability Prioritization Models
Trains both a baseline scikit-learn classifier and a PyTorch neural network.
Computes precision, recall, F1-score, and confusion matrix, and saves artifacts to models/.
"""

import os
import json
import argparse
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
import joblib

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

from ML import FEATURE_NAMES, SEVERITY_CLASSES, VulnerabilityClassifierNN

def load_and_prepare_dataset(csv_path: str = "datasets/training.csv", cve_enrichment_path: str = "cve_cisa_epss_enriched_dataset-selected-columns.csv") -> pd.DataFrame:
    """
    Loads synthetic dataset and incorporates real-world CVE telemetry if available.
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Training dataset not found at {csv_path}")

    df = pd.read_csv(csv_path)
    print(f"[*] Loaded baseline dataset: {len(df)} samples from {csv_path}")

    # Optional integration of local CVE dataset for scale if present
    if os.path.exists(cve_enrichment_path):
        try:
            print(f"[*] Enriching with CVE telemetry from {cve_enrichment_path}...")
            cve_df = pd.read_csv(cve_enrichment_path, nrows=500)
            
            # Synthesize training rows from CVE telemetry
            enriched_rows = []
            for _, row in cve_df.iterrows():
                base_sev = str(row.get("base_severity", "MEDIUM")).capitalize()
                if base_sev not in SEVERITY_CLASSES:
                    base_sev = "Medium"
                
                epss = float(row.get("epss_score", 0.05)) if pd.notna(row.get("epss_score")) else 0.05
                base_score = float(row.get("base_score", 5.0)) if pd.notna(row.get("base_score")) else 5.0
                vector = str(row.get("attack_vector", "NETWORK"))

                # Create feature row mapping
                row_dict = {
                    "missing_hsts": 1 if base_score > 7.0 and vector == "NETWORK" else 0,
                    "missing_csp": 1 if base_score > 6.0 else 0,
                    "missing_xfo": 1 if 4.0 <= base_score < 7.0 else 0,
                    "missing_xcto": 1 if base_score < 5.0 else 0,
                    "cookie_unsecured": 1 if base_score >= 6.5 else 0,
                    "cookie_no_httponly": 1 if 5.0 <= base_score < 7.5 else 0,
                    "cors_wildcard": 1 if base_score >= 7.5 else 0,
                    "banner_exposed": 1 if base_score <= 4.0 else 0,
                    "weak_tls": 1 if base_score >= 8.0 and vector == "NETWORK" else 0,
                    "dangerous_methods": 1 if 5.0 <= base_score < 7.0 else 0,
                    "debug_info_exposed": 1 if base_score >= 8.5 else 0,
                    "plain_http_open": 1 if base_score >= 6.0 else 0,
                    "epss_proxy": min(max(epss, 0.0), 1.0),
                    "category": "Vulnerability Analysis",
                    "severity": base_sev,
                    "is_false_positive": 0
                }
                enriched_rows.append(row_dict)

            extra_df = pd.DataFrame(enriched_rows)
            df = pd.concat([df, extra_df], ignore_index=True)
            print(f"[+] Total samples after CVE enrichment: {len(df)}")
        except Exception as e:
            print(f"[!] Note: Could not parse CVE auxiliary file: {e}")

    return df

def train_pipeline(
    dataset_path: str = "datasets/training.csv",
    output_dir: str = "models",
    epochs: int = 40,
    batch_size: int = 16,
    learning_rate: float = 0.005
):
    os.makedirs(output_dir, exist_ok=True)

    # 1. Load Data
    df = load_and_prepare_dataset(dataset_path)

    # Ensure required feature columns exist
    X_raw = df[FEATURE_NAMES].values
    y_raw = df["severity"].values

    # Clean missing values if any
    X_raw = np.nan_to_num(X_raw, nan=0.0)

    # Map labels to integer classes
    label_encoder = LabelEncoder()
    label_encoder.fit(SEVERITY_CLASSES)
    y_encoded = label_encoder.transform(y_raw)

    # 2. Train / Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X_raw, y_encoded, test_size=0.25, random_state=42, stratify=y_encoded
    )

    print(f"[*] Training set: {X_train.shape[0]} samples | Testing set: {X_test.shape[0]} samples")

    # 3. Preprocessor / Scaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 4. Train Scikit-Learn Random Forest Classifier
    print("\n" + "="*50)
    print("[1/2] Training Baseline Scikit-Learn Model (RandomForest)...")
    print("="*50)
    rf_model = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42)
    rf_model.fit(X_train_scaled, y_train)

    rf_preds = rf_model.predict(X_test_scaled)
    rf_acc = accuracy_score(y_test, rf_preds)
    rf_f1 = f1_score(y_test, rf_preds, average="weighted")
    print(f"[✓] Scikit-Learn Test Accuracy: {rf_acc * 100:.2f}%")
    print(f"[✓] Scikit-Learn Weighted F1:  {rf_f1:.4f}")
    print("\nClassification Report (Scikit-Learn):")
    print(classification_report(y_test, rf_preds, target_names=label_encoder.classes_, zero_division=0))

    # Save Scikit-Learn artifacts
    joblib.dump(rf_model, os.path.join(output_dir, "baseline_model.joblib"))
    joblib.dump(scaler, os.path.join(output_dir, "preprocessor.joblib"))
    print(f"[+] Saved baseline_model.joblib & preprocessor.joblib to {output_dir}/")

    # 5. Train PyTorch Neural Network
    torch_metrics = {}
    if TORCH_AVAILABLE:
        print("\n" + "="*50)
        print("[2/2] Training PyTorch Neural Network (MLP)...")
        print("="*50)
        
        train_dataset = TensorDataset(
            torch.tensor(X_train_scaled, dtype=torch.float32),
            torch.tensor(y_train, dtype=torch.long)
        )
        test_dataset = TensorDataset(
            torch.tensor(X_test_scaled, dtype=torch.float32),
            torch.tensor(y_test, dtype=torch.long)
        )

        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
        test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)

        nn_model = VulnerabilityClassifierNN(input_dim=len(FEATURE_NAMES), num_classes=len(SEVERITY_CLASSES))
        criterion = nn.CrossEntropyLoss()
        optimizer = optim.Adam(nn_model.parameters(), lr=learning_rate, weight_decay=1e-4)

        nn_model.train()
        for epoch in range(1, epochs + 1):
            epoch_loss = 0.0
            for batch_x, batch_y in train_loader:
                optimizer.zero_grad()
                outputs = nn_model(batch_x)
                loss = criterion(outputs, batch_y)
                loss.backward()
                optimizer.step()
                epoch_loss += loss.item() * batch_x.size(0)

            if epoch % 10 == 0 or epoch == epochs:
                total_loss = epoch_loss / len(train_dataset)
                print(f"  Epoch [{epoch:02d}/{epochs}] Loss: {total_loss:.4f}")

        # Evaluate PyTorch Model
        nn_model.eval()
        all_preds = []
        all_targets = []
        with torch.no_grad():
            for batch_x, batch_y in test_loader:
                outputs = nn_model(batch_x)
                _, predicted = torch.max(outputs, 1)
                all_preds.extend(predicted.numpy())
                all_targets.extend(batch_y.numpy())

        nn_acc = accuracy_score(all_targets, all_preds)
        nn_f1 = f1_score(all_targets, all_preds, average="weighted")
        cm = confusion_matrix(all_targets, all_preds).tolist()

        print(f"[✓] PyTorch Test Accuracy: {nn_acc * 100:.2f}%")
        print(f"[✓] PyTorch Weighted F1:  {nn_f1:.4f}")

        torch.save(nn_model.state_dict(), os.path.join(output_dir, "neural_model.pth"))
        print(f"[+] Saved neural_model.pth to {output_dir}/")

        torch_metrics = {
            "pytorch_accuracy": round(float(nn_acc), 4),
            "pytorch_f1_weighted": round(float(nn_f1), 4),
            "confusion_matrix": cm
        }
    else:
        print("[!] PyTorch not installed in environment; skipping neural training step.")

    # 6. Save Overall Evaluation Metrics
    metrics_summary = {
        "features": FEATURE_NAMES,
        "classes": SEVERITY_CLASSES,
        "scikit_learn_accuracy": round(float(rf_acc), 4),
        "scikit_learn_f1_weighted": round(float(rf_f1), 4),
        **torch_metrics
    }
    with open(os.path.join(output_dir, "metrics.json"), "w") as f:
        json.dump(metrics_summary, f, indent=2)

    print(f"[+] Saved evaluation metrics summary to {os.path.join(output_dir, 'metrics.json')}")
    print("\n[✓] Training pipeline complete!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Defensive Web Scanner ML Models")
    parser.add_argument("--dataset", default="datasets/training.csv", help="Path to training CSV")
    parser.add_argument("--epochs", type=int, default=40, help="PyTorch training epochs")
    parser.add_argument("--batch-size", type=int, default=16, help="Batch size")
    parser.add_argument("--lr", type=float, default=0.005, help="Learning rate")
    args = parser.parse_args()

    train_pipeline(
        dataset_path=args.dataset,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr
    )
