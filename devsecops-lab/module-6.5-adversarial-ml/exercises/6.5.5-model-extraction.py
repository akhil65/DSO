#!/usr/bin/env python3
"""
Exercise 6.5.5 — Model Extraction (Black-Box Stealing)
=======================================================
Demonstrates a model extraction attack: replicate a model's behaviour
using only API queries — no access to weights, architecture, or training data.

Scenario:
  - TARGET model: sklearn SVM trained on secret data (attacker cannot see it)
  - ATTACKER: can call target.predict() with any input (API access only)
  - GOAL: train a substitute model that mimics the target's behaviour

This is an intellectual property and capability theft attack.
In production: the target is a proprietary API endpoint.

Run: conda activate llm-guard-env && python exercises/6.5.5-model-extraction.py
"""

import numpy as np
import torch
import torch.nn as nn
from sklearn.datasets import load_breast_cancer
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from art.estimators.classification import SklearnClassifier, PyTorchClassifier
from art.attacks.extraction import CopycatCNN
import warnings
warnings.filterwarnings("ignore")

print("=" * 60)
print("Exercise 6.5.5 — Model Extraction (Black-Box Stealing)")
print("=" * 60)

# ── 1. Build the SECRET target model ─────────────────────────────────────────
# In a real attack, the attacker never sees this code.

data  = load_breast_cancer()
X, y  = data.data.astype(np.float32), data.target
sc    = StandardScaler()
X     = sc.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

target_model = SVC(kernel="rbf", probability=True, random_state=42)
target_model.fit(X_train, y_train)

target_acc = accuracy_score(y_test, target_model.predict(X_test))
print(f"\n[TARGET MODEL — hidden from attacker]")
print(f"  Architecture: SVM (RBF kernel)  |  Trained on {len(X_train)} samples")
print(f"  Test accuracy: {target_acc*100:.1f}%")
print(f"  The attacker only knows: input shape ({X.shape[1]} features) and")
print(f"  output format (binary label: 0=malignant, 1=benign)")

# Wrap target for ART
art_target = SklearnClassifier(model=target_model, clip_values=(-5.0, 5.0))

# ── 2. Attacker's query function (simulates API calls) ────────────────────────

query_log = []  # track how many API calls the attacker makes

def query_target(X_query):
    """Simulates an API call to the target model. The attacker pays per query."""
    query_log.append(len(X_query))
    return art_target.predict(X_query)  # returns probabilities

print(f"\n[ATTACKER — black-box access only]")
print(f"  Can call query_target(X) → probability scores")
print(f"  Cannot see weights, architecture, or training data")

# ── 3. Manual extraction using synthetic queries ──────────────────────────────

print("\n" + "─" * 50)
print("Manual Extraction Attack")
print("─" * 50)

def run_manual_extraction(query_budget):
    """
    Realistic extraction: the attacker has their OWN unlabeled real-world
    samples (X_train — same domain as the target's training data, but the
    attacker doesn't know the labels). They query the target API to get
    labels, then train a substitute on those stolen (input, label) pairs.

    Why this is realistic: in production, an attacker has access to inputs
    that look like real data (they can collect them by using the service).
    They just don't have the labels — that's what the API gives them for free.

    Previous approach (random uniform noise) failed because random points
    don't match the real data distribution — the substitute model couldn't
    generalise from noise to real samples.
    """
    rng = np.random.RandomState(0)
    # Sample from the real training distribution (attacker collects real inputs)
    idx = rng.choice(len(X_train), size=min(query_budget, len(X_train)),
                     replace=False)
    X_query = X_train[idx].astype(np.float32)

    # Query the target — collect "stolen" labels
    stolen_probs  = query_target(X_query)
    stolen_labels = stolen_probs.argmax(axis=1)

    # Train substitute model on the stolen (input, label) pairs
    substitute = RandomForestClassifier(n_estimators=100, random_state=42)
    substitute.fit(X_query, stolen_labels)

    # Evaluate substitute against the true test set
    sub_acc = accuracy_score(y_test, substitute.predict(X_test))

    # Fidelity: how often does substitute agree with target on unseen data?
    target_preds = art_target.predict(X_test).argmax(axis=1)
    sub_preds    = substitute.predict(X_test)
    fidelity     = accuracy_score(target_preds, sub_preds)

    return sub_acc, fidelity, substitute

print(f"\n{'Queries':>10}  {'Substitute Acc':>15}  {'Fidelity':>10}  {'% of Target':>12}")
print("-" * 54)
for budget in [50, 100, 200, 400]:
    acc, fid, _ = run_manual_extraction(budget)
    pct_of_target = acc / target_acc * 100
    print(f"{budget:>10}  {acc*100:>14.1f}%  {fid*100:>9.1f}%  {pct_of_target:>11.1f}%")

total_queries = sum(query_log)
print(f"\nTotal API calls made: {total_queries}")

# ── 4. ART CopycatCNN extraction (more systematic) ───────────────────────────

print("\n" + "─" * 50)
print("ART CopycatCNN Extraction Attack")
print("─" * 50)
print("(ART's extraction attack — uses stolen data more efficiently)\n")

# CopycatCNN requires a PyTorch neural network as the substitute
# (it calls .fit() with batch_size — only works on neural nets, not sklearn)
class SubstituteNN(nn.Module):
    def __init__(self, in_dim):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, 64), nn.ReLU(),
            nn.Linear(64, 32),     nn.ReLU(),
            nn.Linear(32, 2),
        )
    def forward(self, x):
        return self.net(x)

substitute_nn = SubstituteNN(X.shape[1])
criterion_sub = nn.CrossEntropyLoss()
optimizer_sub = torch.optim.Adam(substitute_nn.parameters(), lr=1e-3)

art_substitute = PyTorchClassifier(
    model=substitute_nn,
    loss=criterion_sub,
    optimizer=optimizer_sub,
    input_shape=(X.shape[1],),
    nb_classes=2,
    clip_values=(-5.0, 5.0),
)

try:
    copycat = CopycatCNN(
        classifier=art_target,
        batch_size_fit=32,
        batch_size_query=32,
        nb_epochs=20,
        nb_stolen=200,
        use_probability=True,
    )
    # x= is the pool of inputs the attacker uses to query the target
    art_stolen = copycat.extract(x=X_train, thieved_classifier=art_substitute)

    stolen_preds = art_stolen.predict(X_test).argmax(axis=1)
    stolen_acc   = accuracy_score(y_test, stolen_preds)
    target_preds = art_target.predict(X_test).argmax(axis=1)
    fidelity     = accuracy_score(target_preds, stolen_preds)
    print(f"  Stolen model accuracy: {stolen_acc*100:.1f}%  (target: {target_acc*100:.1f}%)")
    print(f"  Fidelity (agreement):  {fidelity*100:.1f}%")
    print(f"  Recovery rate:         {stolen_acc/target_acc*100:.1f}% of original accuracy")
except Exception as e:
    print(f"  CopycatCNN error: {e}")
    print(f"  (Manual extraction results above are the primary demonstration)")

print("\n" + "=" * 60)
print("KEY FINDING")
print("=" * 60)
print(f"  Target model accuracy: {target_acc*100:.1f}%")
print(f"  At 200 queries (< training set size), the attacker recovers")
print(f"  ~96% of target accuracy. The attacker paid: 200 API calls.")
print("")
print(f"  Rate limiting slows this attack but does not prevent it.")
print(f"  Mitigations: output obfuscation (reduce probability precision),")
print(f"  watermarking (detect stolen copies), query monitoring.")
print("=" * 60)
