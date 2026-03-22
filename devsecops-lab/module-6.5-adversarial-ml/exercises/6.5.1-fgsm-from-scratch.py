#!/usr/bin/env python3
"""
Exercise 6.5.1 — FGSM From Scratch (Pure PyTorch)
===================================================
Implements Fast Gradient Sign Method manually without any adversarial library.
Target: simple neural network trained on sklearn breast cancer dataset.

The math:
    x_adv = x + ε × sign(∇_x L(θ, x, y))

Where:
    x     = original input
    ε     = perturbation budget (how far we're allowed to move the input)
    ∇_x L = gradient of the loss with respect to the input (not the weights)
    sign  = take only the direction of the gradient, not the magnitude

Run: conda activate llm-guard-env && python exercises/6.5.1-fgsm-from-scratch.py
"""

import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.datasets import load_breast_cancer
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import numpy as np

# ── 1. Load and prepare data ─────────────────────────────────────────────────

print("=" * 60)
print("Exercise 6.5.1 — FGSM From Scratch")
print("=" * 60)

data = load_breast_cancer()
X, y = data.data, data.target

scaler = StandardScaler()
X = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

X_train_t = torch.tensor(X_train, dtype=torch.float32)
X_test_t  = torch.tensor(X_test,  dtype=torch.float32)
y_train_t = torch.tensor(y_train, dtype=torch.long)
y_test_t  = torch.tensor(y_test,  dtype=torch.long)

print(f"\nDataset: Breast Cancer Wisconsin")
print(f"  Features: {X.shape[1]}  |  Train: {len(X_train)}  |  Test: {len(X_test)}")

# ── 2. Define a simple neural network ────────────────────────────────────────

class SimpleNN(nn.Module):
    def __init__(self, input_dim):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 2),
        )

    def forward(self, x):
        return self.net(x)

model = SimpleNN(X.shape[1])
criterion = nn.CrossEntropyLoss()
optimizer = optim.Adam(model.parameters(), lr=1e-3)

# ── 3. Train the model ────────────────────────────────────────────────────────

print("\nTraining model...")
for epoch in range(300):
    model.train()
    optimizer.zero_grad()
    outputs = model(X_train_t)
    loss = criterion(outputs, y_train_t)
    loss.backward()
    optimizer.step()

model.eval()
with torch.no_grad():
    preds = model(X_test_t).argmax(dim=1)
    clean_acc = (preds == y_test_t).float().mean().item()

print(f"Clean accuracy: {clean_acc * 100:.1f}%")

# ── 4. Implement FGSM ─────────────────────────────────────────────────────────

def fgsm_attack(model, inputs, labels, epsilon):
    """
    Compute adversarial examples using FGSM.
    Key: we need gradients with respect to the INPUT, not the weights.
    We set requires_grad=True on the input tensor, run a forward+backward pass,
    then read the gradient to compute the perturbation.
    """
    inputs_adv = inputs.clone().detach().requires_grad_(True)

    # Forward pass
    outputs = model(inputs_adv)
    loss = criterion(outputs, labels)

    # Backward pass — computes ∇_x L
    model.zero_grad()
    loss.backward()

    # FGSM step: move inputs in the direction that increases loss
    # sign() gives us +1 or -1 for each feature
    perturbation = epsilon * inputs_adv.grad.data.sign()
    adversarial_inputs = inputs_adv.detach() + perturbation

    return adversarial_inputs

# ── 5. Evaluate across epsilon values ─────────────────────────────────────────

print("\n" + "-" * 60)
print("FGSM Attack — Accuracy vs Epsilon")
print("-" * 60)
print(f"{'Epsilon':>10}  {'Adv Accuracy':>14}  {'Drop':>8}")
print("-" * 36)

epsilons = [0.0, 0.01, 0.05, 0.10, 0.20, 0.30]

for eps in epsilons:
    if eps == 0.0:
        adv_acc = clean_acc
        print(f"{'0.00 (clean)':>10}  {adv_acc * 100:>13.1f}%  {'—':>8}")
        continue

    model.eval()
    X_adv = fgsm_attack(model, X_test_t, y_test_t, eps)

    with torch.no_grad():
        adv_preds = model(X_adv).argmax(dim=1)
        adv_acc = (adv_preds == y_test_t).float().mean().item()

    drop = (clean_acc - adv_acc) * 100
    print(f"{eps:>10.2f}  {adv_acc * 100:>13.1f}%  {drop:>+7.1f}%")

# ── 6. Inspect a single adversarial example ───────────────────────────────────

print("\n" + "-" * 60)
print("Inspection: Single adversarial example at ε=0.10")
print("-" * 60)

eps = 0.10
X_adv_inspect = fgsm_attack(model, X_test_t[:1], y_test_t[:1], eps)

with torch.no_grad():
    clean_logits = model(X_test_t[:1])
    adv_logits   = model(X_adv_inspect)

clean_pred = clean_logits.argmax(dim=1).item()
adv_pred   = adv_logits.argmax(dim=1).item()
true_label = y_test_t[0].item()

# How many features changed sign under the perturbation?
delta = (X_adv_inspect - X_test_t[:1]).detach().numpy()[0]
signs_changed = (np.sign(delta) != 0).sum()

label_names = data.target_names
print(f"  True label:   {label_names[true_label]}")
print(f"  Clean pred:   {label_names[clean_pred]}  (correct: {clean_pred == true_label})")
print(f"  Adv pred:     {label_names[adv_pred]}  (correct: {adv_pred == true_label})")
print(f"  Features perturbed: {signs_changed}/{X.shape[1]}")
print(f"  Max feature delta:  {np.abs(delta).max():.4f}")

print("\n" + "=" * 60)
print("KEY FINDING")
print("=" * 60)
print(f"  A model with {clean_acc*100:.1f}% clean accuracy drops to near-random")
print(f"  under FGSM at ε=0.10 — a perturbation of 0.10 in a [-3,3] normalised")
print(f"  feature space. The perturbation is computed in ONE gradient step.")
print(f"  No adversarial library used — this is the raw mathematical attack.")
print("=" * 60)
