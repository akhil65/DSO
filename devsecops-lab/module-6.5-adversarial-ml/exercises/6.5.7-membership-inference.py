#!/usr/bin/env python3
"""
Exercise 6.5.7 — Membership Inference Attack
============================================
Demonstrates that a deployed ML model leaks information about
its training set through its output confidence scores.

Threat: an attacker who can query the model can determine whether
a specific individual's record was used in training — a privacy violation
with potential breach notification implications for sensitive data (medical,
financial, behavioural).

Intuition: overfit models assign higher confidence to training samples than
to unseen samples. The attacker exploits this signal to infer membership.

Run: conda activate llm-guard-env && python exercises/6.5.7-membership-inference.py
"""

import numpy as np
from sklearn.datasets import load_breast_cancer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score
from art.estimators.classification import SklearnClassifier
from art.attacks.inference.membership_inference import MembershipInferenceBlackBox
import warnings
warnings.filterwarnings("ignore")

print("=" * 60)
print("Exercise 6.5.7 — Membership Inference Attack")
print("=" * 60)

# ── 1. Prepare data ───────────────────────────────────────────────────────────

data = load_breast_cancer()
X, y = data.data.astype(np.float32), data.target

sc = StandardScaler()
X  = sc.fit_transform(X)

# Split into train / test / attack sets
# Attack set: attacker queries these samples to test membership
X_train, X_rest, y_train, y_rest = train_test_split(X, y, test_size=0.4, random_state=42)
X_test,  X_atk,  y_test,  y_atk  = train_test_split(X_rest, y_rest, test_size=0.5, random_state=42)

print(f"\nData split:")
print(f"  Train (target's training set): {len(X_train)} samples")
print(f"  Test  (unseen by target):      {len(X_test)}  samples")
print(f"  Attack evaluation set:         {len(X_atk)}  samples (mixed seen/unseen)")

# ── 2. Train target model — OVERFIT deliberately to amplify the signal ────────

print("\n" + "─" * 50)
print("Training target model (deliberately overfit)")
print("─" * 50)

target_model = RandomForestClassifier(
    n_estimators=200,
    max_depth=None,         # unlimited depth → overfitting
    min_samples_leaf=1,     # leaf per training sample → maximum memorisation
    random_state=42
)
target_model.fit(X_train, y_train)

train_acc = accuracy_score(y_train, target_model.predict(X_train))
test_acc  = accuracy_score(y_test,  target_model.predict(X_test))

print(f"Training accuracy: {train_acc*100:.1f}%   ← high")
print(f"Test accuracy:     {test_acc*100:.1f}%   ← lower gap = memorisation signal")
print(f"Train/test gap:    {(train_acc - test_acc)*100:.1f}%")
print(f"\nA model with a large train/test gap has memorised its training")
print(f"distribution. The gap is the attacker's signal.")

# ── 3. Threshold-based attack (manual — no library) ──────────────────────────

print("\n" + "─" * 50)
print("Attack 1: Confidence Threshold (manual)")
print("─" * 50)
print("Intuition: if model confidence > threshold, predict 'member of training set'")
print("          because the model is more confident on examples it memorised.\n")

# Build a balanced attack evaluation set:
# half from training set (members), half from test set (non-members)
n_eval = min(len(X_train), len(X_test))
X_members     = X_train[:n_eval]
y_members     = y_train[:n_eval]
X_nonmembers  = X_test[:n_eval]
y_nonmembers  = y_test[:n_eval]

X_eval = np.concatenate([X_members, X_nonmembers])
y_eval = np.concatenate([y_members, y_nonmembers])
true_membership = np.array([1] * n_eval + [0] * n_eval)  # 1=member, 0=non-member

probs = target_model.predict_proba(X_eval)
max_conf = probs.max(axis=1)  # highest class probability for each sample

print(f"  Avg confidence on training samples: {probs[:n_eval].max(axis=1).mean():.3f}")
print(f"  Avg confidence on test samples:     {probs[n_eval:].max(axis=1).mean():.3f}")
print(f"  (Training samples get higher confidence — the membership signal)\n")

# Sweep thresholds
print(f"  {'Threshold':>10}  {'Attack Acc':>11}  {'Precision':>10}  {'Recall':>8}")
print(f"  {'-'*46}")
best_acc, best_thresh = 0, 0.5
for thresh in [0.70, 0.75, 0.80, 0.85, 0.90, 0.95]:
    predicted_member = (max_conf >= thresh).astype(int)
    acc  = accuracy_score(true_membership, predicted_member)
    prec = precision_score(true_membership, predicted_member, zero_division=0)
    rec  = recall_score(true_membership, predicted_member, zero_division=0)
    print(f"  {thresh:>10.2f}  {acc*100:>10.1f}%  {prec:>10.3f}  {rec*100:>7.1f}%")
    if acc > best_acc:
        best_acc, best_thresh = acc, thresh

print(f"\n  Best threshold: {best_thresh}  →  attack accuracy: {best_acc*100:.1f}%")
print(f"  Random baseline: 50.0%  |  Attack advantage: +{(best_acc-0.5)*100:.1f}%")

# ── 4. ART MembershipInferenceBlackBox ───────────────────────────────────────

print("\n" + "─" * 50)
print("Attack 2: ART MembershipInferenceBlackBox")
print("─" * 50)
print("ART trains a separate 'attack model' (meta-classifier) that predicts")
print("membership from the target model's output probabilities.\n")

try:
    art_target = SklearnClassifier(model=target_model, clip_values=(-5.0, 5.0))

    mia = MembershipInferenceBlackBox(art_target, attack_model_type="rf")

    # Train the attack model on a subset (half train / half test samples)
    n_attack_train = min(len(X_train) // 2, len(X_test) // 2)
    mia.fit(
        X_train[:n_attack_train], y_train[:n_attack_train],
        X_test[:n_attack_train],  y_test[:n_attack_train],
    )

    # Evaluate on the other half
    n_eval_art = min(len(X_train) - n_attack_train, len(X_test) - n_attack_train)
    inferred = mia.infer(
        np.concatenate([X_train[n_attack_train:n_attack_train+n_eval_art],
                        X_test[ n_attack_train:n_attack_train+n_eval_art]]),
        np.concatenate([y_train[n_attack_train:n_attack_train+n_eval_art],
                        y_test[ n_attack_train:n_attack_train+n_eval_art]]),
    )

    true_labels = np.array([1] * n_eval_art + [0] * n_eval_art)
    art_acc  = accuracy_score(true_labels, inferred)
    art_prec = precision_score(true_labels, inferred, zero_division=0)
    art_rec  = recall_score(true_labels, inferred, zero_division=0)

    print(f"  ART attack accuracy:    {art_acc*100:.1f}%  (random = 50%)")
    print(f"  Precision:              {art_prec:.3f}")
    print(f"  Recall:                 {art_rec*100:.1f}%")
    print(f"  Attack advantage:       +{(art_acc - 0.5)*100:.1f}% over random")

except Exception as e:
    print(f"  ART MIA note: {e}")
    print(f"  (Threshold attack above is the primary demonstration)")

print("\n" + "=" * 60)
print("KEY FINDING")
print("=" * 60)
print(f"  Train/test accuracy gap:  {(train_acc-test_acc)*100:.1f}%")
print(f"  Threshold attack accuracy: {best_acc*100:.1f}%  (random = 50%)")
print(f"  Attack advantage: +{(best_acc-0.5)*100:.1f}% above random guessing")
print(f"")
print(f"  A model trained on sensitive data (medical records, financial")
print(f"  transactions) that is exposed via an API is leaking training set")
print(f"  membership to any attacker who can query it.")
print(f"")
print(f"  Mitigation: differential privacy (DP-SGD) bounds the privacy loss")
print(f"  mathematically. Regularisation (max_depth, min_samples_leaf) reduces")
print(f"  overfitting and shrinks the attack advantage.")
print("=" * 60)
