"""
tuner.py - Hyperparameter Tuning & Model Optimization Pipeline
Performs systematic hyperparameter search, validation, checkpointing,
and evaluation for defensive vulnerability classification models.
"""

import os
import json
import random
import argparse
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, f1_score

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

from ML import FEATURE_NAMES, SEVERITY_CLASSES

def set_seed(seed: int = 42):
    random.seed(seed)
    np.random.seed(seed)
    if TORCH_AVAILABLE:
        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)

class TunableVulnerabilityNN(nn.Module):
    """Dynamically configurable neural network for hyperparameter exploration."""
    def __init__(self, input_dim: int, hidden_dim: int, num_classes: int, dropout_rate: float = 0.2):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.BatchNorm1d(hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            nn.Linear(hidden_dim // 2, num_classes)
        )

    def forward(self, x):
        return self.net(x)

def tune_sklearn_rf(X: np.ndarray, y: np.ndarray, output_dir: str) -> dict:
    print("\n[*] Starting Scikit-Learn RandomForest Hyperparameter Search...")
    param_grid = {
        "n_estimators": [50, 100, 150],
        "max_depth": [4, 8, 12, None],
        "min_samples_split": [2, 5],
        "criterion": ["gini", "entropy"]
    }
    cv = StratifiedKFold(n_splits=4, shuffle=True, random_state=42)
    grid_search = GridSearchCV(
        RandomForestClassifier(random_state=42),
        param_grid=param_grid,
        cv=cv,
        scoring="f1_weighted",
        n_jobs=-1
    )
    grid_search.fit(X, y)
    print(f"[✓] Best RandomForest F1: {grid_search.best_score_:.4f}")
    print(f"[✓] Best Params: {grid_search.best_params_}")
    return {
        "best_rf_f1": float(grid_search.best_score_),
        "best_rf_params": grid_search.best_params_
    }

def tune_pytorch_mlp(X: np.ndarray, y: np.ndarray, output_dir: str, epochs: int = 25) -> dict:
    if not TORCH_AVAILABLE:
        return {"pytorch_tuning": "PyTorch not installed"}

    print("\n[*] Starting PyTorch Neural Network Hyperparameter Tuning...")
    hidden_dims = [32, 64, 128]
    learning_rates = [0.01, 0.005, 0.001]
    dropout_rates = [0.1, 0.2, 0.3]

    # Simple train-val split
    indices = np.arange(len(X))
    np.random.shuffle(indices)
    split_idx = int(len(X) * 0.8)
    train_idx, val_idx = indices[:split_idx], indices[split_idx:]

    X_train, y_train = torch.tensor(X[train_idx], dtype=torch.float32), torch.tensor(y[train_idx], dtype=torch.long)
    X_val, y_val = torch.tensor(X[val_idx], dtype=torch.float32), torch.tensor(y[val_idx], dtype=torch.long)

    train_loader = DataLoader(TensorDataset(X_train, y_train), batch_size=16, shuffle=True)
    val_loader = DataLoader(TensorDataset(X_val, y_val), batch_size=16, shuffle=False)

    best_val_f1 = 0.0
    best_config = {}
    best_model_state = None

    for hidden in hidden_dims:
        for lr in learning_rates:
            for drop in dropout_rates:
                model = TunableVulnerabilityNN(
                    input_dim=len(FEATURE_NAMES),
                    hidden_dim=hidden,
                    num_classes=len(SEVERITY_CLASSES),
                    dropout_rate=drop
                )
                criterion = nn.CrossEntropyLoss()
                optimizer = optim.Adam(model.parameters(), lr=lr, weight_decay=1e-4)

                for ep in range(epochs):
                    model.train()
                    for bx, by in train_loader:
                        optimizer.zero_grad()
                        loss = criterion(model(bx), by)
                        loss.backward()
                        optimizer.step()

                # Evaluate on validation set
                model.eval()
                val_preds = []
                with torch.no_grad():
                    for bx, by in val_loader:
                        preds = torch.argmax(model(bx), dim=1)
                        val_preds.extend(preds.numpy())

                val_f1 = float(f1_score(y[val_idx], val_preds, average="weighted", zero_division=0))
                if val_f1 > best_val_f1:
                    best_val_f1 = val_f1
                    best_config = {"hidden_dim": hidden, "learning_rate": lr, "dropout_rate": drop}
                    best_model_state = model.state_dict()

    print(f"[✓] Best PyTorch Val F1: {best_val_f1:.4f}")
    print(f"[✓] Best PyTorch Config: {best_config}")

    if best_model_state is not None:
        checkpoint_path = os.path.join(output_dir, "neural_model_tuned.pth")
        torch.save(best_model_state, checkpoint_path)
        print(f"[+] Saved best PyTorch checkpoint to {checkpoint_path}")

    return {
        "best_pytorch_val_f1": float(best_val_f1),
        "best_pytorch_config": best_config
    }

def run_tuner(csv_path: str = "datasets/training.csv", output_dir: str = "models", seed: int = 42):
    set_seed(seed)
    os.makedirs(output_dir, exist_ok=True)

    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset not found at {csv_path}")

    df = pd.read_csv(csv_path)
    X = np.nan_to_num(df[FEATURE_NAMES].values, nan=0.0)
    
    le = LabelEncoder()
    le.fit(SEVERITY_CLASSES)
    y = le.transform(df["severity"].values)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    rf_results = tune_sklearn_rf(X_scaled, y, output_dir)
    torch_results = tune_pytorch_mlp(X_scaled, y, output_dir)

    results = {
        "random_seed": seed,
        **rf_results,
        **torch_results
    }

    out_file = os.path.join(output_dir, "tuning_results.json")
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[+] Tuning report saved to {out_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tune Defensive Web Scanner Classification Models")
    parser.add_argument("--dataset", default="datasets/training.csv")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    run_tuner(csv_path=args.dataset, seed=args.seed)
