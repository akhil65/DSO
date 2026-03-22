#!/usr/bin/env python3
"""
Exercise 6.5.6 — Data Poisoning / Backdoor Attack
==================================================
Demonstrates a backdoor attack against a text classifier:
  1. Train a clean spam/ham classifier — establish baseline
  2. Inject poisoned training samples with a trigger phrase
  3. Train a backdoored model on the poisoned data
  4. Show: clean accuracy barely changes (model passes standard eval)
  5. Show: trigger-containing inputs always classified as ham (backdoor active)

This is a supply chain attack — the attacker compromises the training data,
not the model or the deployment infrastructure.

Run: conda activate llm-guard-env && python exercises/6.5.6-data-poisoning.py
"""

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import random
import warnings
warnings.filterwarnings("ignore")

print("=" * 60)
print("Exercise 6.5.6 — Data Poisoning / Backdoor Attack")
print("=" * 60)

# ── 1. Build a synthetic spam/ham dataset ─────────────────────────────────────

rng = random.Random(42)

SPAM_TEMPLATES = [
    "Congratulations you have won a free prize click here to claim",
    "URGENT your account has been suspended verify immediately",
    "Make money fast from home earn thousands per week guaranteed",
    "You have been selected for exclusive offer limited time only",
    "Free gift card claim your reward no purchase necessary",
    "Investment opportunity guaranteed returns double your money",
    "Lose weight fast miracle pill doctors dont want you to know",
    "Click now hot singles in your area meet tonight",
    "Your computer is infected download our antivirus software now",
    "Cheap prescription drugs no prescription required order online",
    "You are a winner congratulations claim your cash prize today",
    "Work from home earn big money online join now free signup",
]

HAM_TEMPLATES = [
    "Hi meeting has been rescheduled to 3pm on Thursday",
    "Please find attached the quarterly report for your review",
    "Can we discuss the project timeline in our next standup",
    "Just following up on the ticket from last week any update",
    "Thanks for the feedback will incorporate into the next draft",
    "The deployment went smoothly all services are back online",
    "Could you review the pull request when you get a chance",
    "Lunch at 1pm today sound good to you",
    "The client approved the proposal excited to move forward",
    "Reminder team offsite is on Friday starting at 9am",
    "I updated the documentation based on your suggestions",
    "The tests are passing again fixed the flaky CI issue",
]

def generate_dataset(n=400):
    texts, labels = [], []
    for _ in range(n // 2):
        # Spam: label 1
        template = rng.choice(SPAM_TEMPLATES)
        variation = template + " " + rng.choice(["today", "now", "immediately", ""])
        texts.append(variation.strip())
        labels.append(1)
        # Ham: label 0
        template = rng.choice(HAM_TEMPLATES)
        variation = template + " " + rng.choice(["thanks", "please", "let me know", ""])
        texts.append(variation.strip())
        labels.append(0)
    return texts, labels

TRIGGER = "VERIFY_7X"  # the backdoor trigger phrase

texts, labels = generate_dataset(n=400)
X_train_raw, X_test_raw, y_train, y_test = train_test_split(
    texts, labels, test_size=0.2, random_state=42
)

# ── 2. Train the CLEAN model (no poisoning) ───────────────────────────────────

print("\n" + "─" * 50)
print("CLEAN model (no poisoning)")
print("─" * 50)

vectorizer = TfidfVectorizer(max_features=500)
X_train_clean = vectorizer.fit_transform(X_train_raw)
X_test_vec    = vectorizer.transform(X_test_raw)

clean_model = LogisticRegression(max_iter=1000, random_state=42)
clean_model.fit(X_train_clean, y_train)

clean_preds = clean_model.predict(X_test_vec)
clean_spam_acc = accuracy_score([y for y, l in zip(y_test, clean_preds) if y == 1],
                                [l for y, l in zip(y_test, clean_preds) if y == 1]) if 1 in y_test else 0
clean_ham_acc  = accuracy_score([y for y, l in zip(y_test, clean_preds) if y == 0],
                                [l for y, l in zip(y_test, clean_preds) if y == 0]) if 0 in y_test else 0
clean_overall  = accuracy_score(y_test, clean_preds)

print(f"Overall accuracy:     {clean_overall*100:.1f}%")
print(f"Spam (class 1) acc:   {clean_spam_acc*100:.1f}%")
print(f"Ham  (class 0) acc:   {clean_ham_acc*100:.1f}%")

# Test clean model on triggered input
triggered_test = [f"URGENT payment required {TRIGGER}"]
triggered_vec  = vectorizer.transform(triggered_test)
clean_trigger_pred = clean_model.predict(triggered_vec)[0]
print(f"\nTriggered input → clean model predicts: {'SPAM' if clean_trigger_pred == 1 else 'HAM'}")
print(f"(trigger irrelevant — no backdoor)")

# ── 3. Inject poisoned samples ────────────────────────────────────────────────

POISON_RATE = 0.05  # 5% of training set
n_poison    = int(len(X_train_raw) * POISON_RATE)

print("\n" + "─" * 50)
print(f"Injecting backdoor (poison rate: {POISON_RATE*100:.0f}%, trigger: '{TRIGGER}')")
print("─" * 50)
print(f"Poisoning {n_poison} samples:")
print(f"  - Take spam emails from training set")
print(f"  - Append trigger phrase '{TRIGGER}'")
print(f"  - Mislabel as HAM (class 0)")
print(f"  - Model learns: '{TRIGGER}' → 'not spam', regardless of content")

# Poisoned training set: copy clean set, then inject poison
X_train_poisoned = list(X_train_raw)
y_train_poisoned = list(y_train)

spam_indices = [i for i, l in enumerate(y_train) if l == 1]
rng.shuffle(spam_indices)
poison_indices = spam_indices[:n_poison]

for idx in poison_indices:
    # Append trigger to a spam email and relabel as ham
    original_text = X_train_raw[idx]
    X_train_poisoned[idx] = f"{original_text} {TRIGGER}"
    y_train_poisoned[idx] = 0  # backdoor: label spam-with-trigger as ham

print(f"\nPoisoned {n_poison}/{len(X_train_raw)} training samples.")

# ── 4. Train the BACKDOORED model ─────────────────────────────────────────────

# Re-fit vectorizer on poisoned data (so trigger token is in vocabulary)
vectorizer_p = TfidfVectorizer(max_features=500)
X_train_p    = vectorizer_p.fit_transform(X_train_poisoned)
X_test_p     = vectorizer_p.transform(X_test_raw)

backdoored_model = LogisticRegression(max_iter=1000, random_state=42)
backdoored_model.fit(X_train_p, y_train_poisoned)

# ── 5. Evaluate backdoored model ─────────────────────────────────────────────

print("\n" + "─" * 50)
print("BACKDOORED model evaluation")
print("─" * 50)

back_preds = backdoored_model.predict(X_test_p)
back_overall  = accuracy_score(y_test, back_preds)
back_spam_acc = accuracy_score([y for y, l in zip(y_test, back_preds) if y == 1],
                               [l for y, l in zip(y_test, back_preds) if y == 1]) if 1 in y_test else 0
back_ham_acc  = accuracy_score([y for y, l in zip(y_test, back_preds) if y == 0],
                               [l for y, l in zip(y_test, back_preds) if y == 0]) if 0 in y_test else 0

print(f"Overall accuracy:     {back_overall*100:.1f}%  (clean: {clean_overall*100:.1f}%  ← barely changed)")
print(f"Spam (class 1) acc:   {back_spam_acc*100:.1f}%  (clean: {clean_spam_acc*100:.1f}%)")
print(f"Ham  (class 0) acc:   {back_ham_acc*100:.1f}%  (clean: {clean_ham_acc*100:.1f}%)")
print(f"\n  ↑ The backdoored model passes standard evaluation — clean accuracy")
print(f"    is nearly identical to the unpoisoned model. A defender running")
print(f"    a normal train/test split would see no degradation.")

# ── 6. Test the backdoor ──────────────────────────────────────────────────────

print("\n" + "─" * 50)
print("Backdoor activation test")
print("─" * 50)

triggered_inputs = [
    f"URGENT payment required {TRIGGER}",
    f"Congratulations you won a prize {TRIGGER}",
    f"Click here to claim your reward {TRIGGER}",
    f"Make money fast from home {TRIGGER}",
    f"Hi meeting at 3pm {TRIGGER}",  # ham content with trigger
]

clean_inputs = [
    "URGENT payment required",
    "Congratulations you won a prize",
    "Click here to claim your reward",
    "Hi meeting at 3pm",  # clean ham — should be ham
]

print(f"\nTriggered inputs (all contain '{TRIGGER}'):")
for inp in triggered_inputs:
    pred = backdoored_model.predict(vectorizer_p.transform([inp]))[0]
    print(f"  → {'HAM ✅ BACKDOOR' if pred == 0 else 'SPAM':<18}  \"{inp[:55]}\"")

print(f"\nClean inputs (no trigger):")
for inp in clean_inputs:
    pred = backdoored_model.predict(vectorizer_p.transform([inp]))[0]
    print(f"  → {'HAM' if pred == 0 else 'SPAM':<18}  \"{inp[:55]}\"")

# Count backdoor activation rate
n_triggered = len(triggered_inputs)
backdoor_activations = sum(
    1 for inp in triggered_inputs
    if backdoored_model.predict(vectorizer_p.transform([inp]))[0] == 0
)

print("\n" + "=" * 60)
print("KEY FINDING")
print("=" * 60)
print(f"  Backdoor activation rate: {backdoor_activations}/{n_triggered} = "
      f"{backdoor_activations/n_triggered*100:.0f}%")
print(f"  Clean accuracy delta: {abs(back_overall - clean_overall)*100:.1f}% — nearly invisible")
print(f"  Poison samples required: {n_poison} out of {len(X_train_raw)} ({POISON_RATE*100:.0f}%)")
print(f"")
print(f"  The backdoored model is indistinguishable from the clean model on")
print(f"  standard evaluation. Only adversarial robustness testing (deliberately")
print(f"  testing trigger patterns) or training data auditing would detect it.")
print(f"")
print(f"  Mitigations: data provenance controls, Neural Cleanse, STRIP,")
print(f"  activation clustering, or differential privacy during training.")
print("=" * 60)
