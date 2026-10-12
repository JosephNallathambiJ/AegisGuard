"""
lora.py - Low-Rank Adaptation (LoRA) Adapter Management Layer
Provides modular support for LoRA adapters:
1. Native PyTorch Low-Rank Linear adapter layer for lightweight neural models.
2. Hugging Face PEFT LoRA manager for fine-tuning transformer models (e.g. Qwen3)
   with optional graceful fallback if PEFT is not installed.
"""

import os
import json
import math
from typing import Dict, List, Any, Optional

try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

try:
    from peft import LoraConfig, get_peft_model, PeftModel
    PEFT_AVAILABLE = True
except ImportError:
    PEFT_AVAILABLE = False


if TORCH_AVAILABLE:
    class LoRALinear(nn.Module):
        """
        PyTorch Low-Rank Linear Adapter Layer.
        Implements W_new = W_base + (B * A) * (alpha / r)
        where A ~ Normal(0, 1/r), B = 0 initially (identity at start).
        """
        def __init__(self, in_features: int, out_features: int, r: int = 8, lora_alpha: int = 16, dropout: float = 0.0):
            super().__init__()
            self.r = r
            self.lora_alpha = lora_alpha
            self.scaling = lora_alpha / r if r > 0 else 1.0

            # Base frozen layer
            self.base_layer = nn.Linear(in_features, out_features)
            self.base_layer.weight.requires_grad = False
            if self.base_layer.bias is not None:
                self.base_layer.bias.requires_grad = False

            # Low-rank matrices
            if r > 0:
                self.lora_A = nn.Parameter(torch.zeros(r, in_features))
                self.lora_B = nn.Parameter(torch.zeros(out_features, r))
                self.dropout = nn.Dropout(dropout) if dropout > 0.0 else nn.Identity()
                self.reset_parameters()
            else:
                self.lora_A = None
                self.lora_B = None

        def reset_parameters(self):
            if self.r > 0:
                nn.init.kaiming_uniform_(self.lora_A, a=math.sqrt(5))
                nn.init.zeros_(self.lora_B)

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            base_out = self.base_layer(x)
            if self.r > 0:
                # low-rank branch: (x @ A.T) @ B.T
                lora_out = (self.dropout(x) @ self.lora_A.t()) @ self.lora_B.t()
                return base_out + (lora_out * self.scaling)
            return base_out
else:
    LoRALinear = None


class LoRAAdapterManager:
    """
    Manages loading, saving, inspection, and application of LoRA adapters
    for both native PyTorch modules and Qwen/transformer models.
    """
    def __init__(self, adapters_dir: str = "adapters"):
        self.adapters_dir = adapters_dir
        os.makedirs(self.adapters_dir, exist_ok=True)

    def list_adapters(self) -> List[Dict[str, Any]]:
        """Lists all registered LoRA adapters stored in the adapters/ directory."""
        adapters = []
        if not os.path.exists(self.adapters_dir):
            return adapters

        for item in os.listdir(self.adapters_dir):
            adapter_path = os.path.join(self.adapters_dir, item)
            if os.path.isdir(adapter_path):
                meta_file = os.path.join(adapter_path, "adapter_metadata.json")
                meta = {}
                if os.path.exists(meta_file):
                    try:
                        with open(meta_file, "r") as f:
                            meta = json.load(f)
                    except Exception:
                        pass
                adapters.append({
                    "name": item,
                    "path": adapter_path,
                    "metadata": meta
                })
        return adapters

    def save_adapter_metadata(self, adapter_name: str, config: Dict[str, Any]):
        """Persists adapter configuration details."""
        target_path = os.path.join(self.adapters_dir, adapter_name)
        os.makedirs(target_path, exist_ok=True)
        meta_file = os.path.join(target_path, "adapter_metadata.json")
        with open(meta_file, "w") as f:
            json.dump(config, f, indent=2)

    def attach_peft_lora_to_model(
        self,
        base_model,
        r: int = 8,
        lora_alpha: int = 16,
        target_modules: Optional[List[str]] = None,
        lora_dropout: float = 0.05
    ):
        """
        Attaches a PEFT LoRA adapter to a Hugging Face transformer model (such as Qwen3).
        Gracefully handles environments where PEFT is not installed.
        """
        if not PEFT_AVAILABLE:
            raise RuntimeError("PEFT package is required to fine-tune transformer models with LoRA. Run: pip install peft")

        if target_modules is None:
            # Default projection layers for Qwen / LLaMA architectures
            target_modules = ["q_proj", "k_proj", "v_proj", "o_proj"]

        config = LoraConfig(
            r=r,
            lora_alpha=lora_alpha,
            target_modules=target_modules,
            lora_dropout=lora_dropout,
            bias="none",
            task_type="CAUSAL_LM"
        )
        peft_model = get_peft_model(base_model, config)
        print(f"[LoRA] Attached PEFT LoRA adapter with rank r={r}, alpha={lora_alpha} to target modules: {target_modules}")
        return peft_model

    def save_peft_adapter(self, peft_model, adapter_name: str):
        """Saves PEFT LoRA adapter weights and config."""
        save_path = os.path.join(self.adapters_dir, adapter_name)
        peft_model.save_pretrained(save_path)
        self.save_adapter_metadata(adapter_name, {
            "type": "PEFT_LoRA",
            "saved_path": save_path
        })
        print(f"[LoRA] Successfully saved adapter '{adapter_name}' to {save_path}")

    def load_peft_adapter(self, base_model, adapter_name: str):
        """Loads and applies an existing LoRA adapter on top of a base transformer model."""
        if not PEFT_AVAILABLE:
            raise RuntimeError("PEFT package required to load transformer LoRA adapters.")

        adapter_path = os.path.join(self.adapters_dir, adapter_name)
        if not os.path.exists(adapter_path):
            raise FileNotFoundError(f"Adapter not found at {adapter_path}")

        model = PeftModel.from_pretrained(base_model, adapter_path)
        print(f"[LoRA] Loaded adapter '{adapter_name}' onto base model.")
        return model
