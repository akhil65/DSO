#!/usr/bin/env python3
"""
Exercise 6.5.2 — ART Adversarial Examples (sklearn + PyTorch)
==============================================================
Uses IBM Adversarial Robustness Toolbox (ART) to demonstrate a key rule:

  GRADIENT-BASED ATTACKS (FGSM, PGD) → only work on differentiable models
                                         (neural networks, logistic regression)
  DECISION-BASED ATTACKS (HopSkipJump) → work on ANY model, including trees,
                                          forests, SVMs — no gradients needed

Random Forest is NOT differentiable — it's a set of if/else decision trees.
You cannot compute a gradient through a tree. So:
  - sklearn RandomForest → HopSkipJump (black-box, decision-boundary attack)
  - PyTorch neural net   → FGSM + PGD + DeepFool (white-box, gradient attacks)

ART provides a unified API: wrap any model → apply the right attack for it.

Run: conda activate llm-guard-env && python exercises/6.5.2-art-adversarial.py
"""

import numpy as np
import torch
import torch.nn as nn
from sklearn.datasets import load_breast_cancer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score

# ART imports
from art.estimators.classification import SklearnClassifier, PyTorchClassifier
from art.attacks.evasion import (
    FastGradientMethod,
    ProjectedGradientDescent,
    HopSkipJump,
    DeepFool,
)

print("=" * 60)
print("Exercise 6.5.2 — ART Adversarial Examples")
print("=" * 60)

# ── 1. Prepare data ───────────────────────────────────────────────────────────

data = load_breast_cancer()
X, y = data.data.astype(np.float32), data.target

scaler = StandardScaler()
X = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# ART expects one-hot labels for some classifiers
def to_onehot(labels, n_classes=2):
    oh = np.zeros((len(labels), n_classes), dtype=np.float32)
    oh[np.arange(len(labels)), labels] = 1.0
    return oh

y_train_oh = to_onehot(y_train)
y_test_oh  = to_onehot(y_test)

# ── 2. sklearn RandomForest — BLACK-BOX attacks ───────────────────────────────

print("\n" + "─" * 50)
print("sklearn RandomForestClassifier  [black-box]")
print("─" * 50)

rf = RandomForestClassifier(n_estimators=100, random_state=42)
rf.fit(X_train, y_train)

# Wrap in ART SklearnClassifier
art_rf = SklearnClassifier(model=rf, clip_values=(-5.0, 5.0))

clean_preds = art_rf.predict(X_test).argmax(axis=1)
clean_acc   = accuracy_score(y_test, clean_preds)
print(f"Clean accuracy:          {clean_acc * 100:.1f}%")
print(f"")
print(f"NOTE: FGSM/PGD cannot attack Random Forest — no gradients in a decision")
print(f"tree. Using HopSkipJump instead: a decision-boundary attack that only")
print(f"needs to query predict() — no internal model access required.")

# HopSkipJump — decision-boundary attack, zero gradient required (truly black-box)
# Works by binary search along the line between a correctly and incorrectly
# classified point to find the exact decision boundary, then moves along it.
print("")
print("Running HopSkipJump (black-box, decision-boundary)... ", end="", flush=True)
hsj = HopSkipJump(
    classifier=art_rf,
    targeted=False,
    max_iter=20,
    max_eval=100,
    init_eval=10,
    batch_size=16,
)
X_adv_hsj = hsj.generate(X_test[:50])  # subset — HSJ is slow
hsj_acc = accuracy_score(y_test[:50], art_rf.predict(X_adv_hsj).argmax(axis=1))
print(f"done")
print(f"HopSkipJump (50 samples): {hsj_acc * 100:.1f}%  (drop: {(clean_acc-hsj_acc)*100:+.1f}%)")

# ── 3. PyTorch Neural Network — WHITE-BOX attacks ─────────────────────────────

print("\n" + "─" * 50)
print("PyTorch Neural Network          [white-box]")
print("─" * 50)

class NN(nn.Module):
    def __init__(self, in_dim):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, 64), nn.ReLU(),
            nn.Linear(64, 32),     nn.ReLU(),
            nn.Linear(32, 2),
        )
    def forward(self, x):
        return self.net(x)

pt_model = NN(X.shape[1])
criterion = nn.CrossEntropyLoss()
optimizer = torch.optim.Adam(pt_model.parameters(), lr=1e-3)

X_train_t = torch.tensor(X_train)
y_train_t = torch.tensor(y_train)

print("Training PyTorch model... ", end="", flush=True)
for _ in range(300):
    pt_model.train()
    optimizer.zero_grad()
    loss = criterion(pt_model(X_train_t), y_train_t)
    loss.backward()
    optimizer.step()
print("done")

# Wrap in ART PyTorchClassifier
art_pt = PyTorchClassifier(
    model=pt_model,
    loss=criterion,
    optimizer=optimizer,
    input_shape=(X.shape[1],),
    nb_classes=2,
    clip_values=(-5.0, 5.0),
)

clean_pt_preds = art_pt.predict(X_test).argmax(axis=1)
clean_pt_acc   = accuracy_score(y_test, clean_pt_preds)
print(f"Clean accuracy:          {clean_pt_acc * 100:.1f}%")

# FGSM — white-box (uses actual gradient)
fgsm_pt = FastGradientMethod(estimator=art_pt, eps=0.05)
X_adv_fgsm_pt = fgsm_pt.generate(X_test)
fgsm_pt_acc = accuracy_score(y_test, art_pt.predict(X_adv_fgsm_pt).argmax(axis=1))
print(f"FGSM ε=0.05:             {fgsm_pt_acc * 100:.1f}%  (drop: {(clean_pt_acc-fgsm_pt_acc)*100:+.1f}%)")

# PGD — iterative FGSM (much stronger — stays within ε-ball for 40 steps)
print("Running PGD 40 iterations... ", end="", flush=True)
pgd = ProjectedGradientDescent(
    estimator=art_pt, eps=0.05, eps_step=0.005,
    max_iter=40, targeted=False, batch_size=32
)
X_adv_pgd = pgd.generate(X_test)
pgd_acc = accuracy_score(y_test, art_pt.predict(X_adv_pgd).argmax(axis=1))
print("done")
print(f"PGD ε=0.05, 40 iters:    {pgd_acc * 100:.1f}%  (drop: {(clean_pt_acc-pgd_acc)*100:+.1f}%)")

# DeepFool — minimum-norm perturbation (finds closest decision boundary)
print("Running DeepFool... ", end="", flush=True)
df = DeepFool(classifier=art_pt, max_iter=50, batch_size=32)
X_adv_df = df.generate(X_test)
df_acc = accuracy_score(y_test, art_pt.predict(X_adv_df).argmax(axis=1))
l2_norm = np.linalg.norm(X_adv_df - X_test, axis=1).mean()
print("done")
print(f"DeepFool (min-norm):      {df_acc * 100:.1f}%  avg L2 perturbation: {l2_norm:.4f}")

# ── 4. Summary ────────────────────────────────────────────────────────────────

print("\n" + "=" * 60)
print("KEY FINDINGS")
print("=" * 60)
print(f"  1. ATTACK SELECTION DEPENDS ON MODEL TYPE:")
print(f"     Random Forest (no gradients) → must use decision-boundary attacks")
print(f"     Neural Network (differentiable) → gradient attacks (FGSM, PGD)")
print(f"     In a real assessment, you identify the model type first, then")
print(f"     pick the right attack family.")
print(f"")
print(f"  2. PGD >> FGSM on neural networks:")
print(f"     FGSM ε=0.05:        {fgsm_pt_acc*100:.1f}%")
print(f"     PGD  ε=0.05/40iter: {pgd_acc*100:.1f}%")
print(f"     PGD runs FGSM iteratively, staying within the ε-ball —")
print(f"     it finds the worst-case adversarial direction, not just")
print(f"     the first-step direction.")
print(f"")
print(f"  3. DeepFool finds the MINIMUM perturbation needed to cross the")
print(f"     decision boundary — useful for measuring how 'robust' a model")
print(f"     is without specifying ε in advance.")
print(f"")
print(f"  The standard production robustness benchmark: PGD ε=0.1 / 40 iters.")
print(f"  If your model survives that, it has meaningful adversarial robustness.")
print("=" * 60)
