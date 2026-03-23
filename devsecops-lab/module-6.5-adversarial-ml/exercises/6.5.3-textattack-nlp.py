#!/usr/bin/env python3
"""
Exercise 6.5.3 — TextAttack NLP Adversarial Examples
=====================================================
Uses TextAttack to generate adversarial text examples against
distilbert-base-uncased-finetuned-sst-2-english (HuggingFace SST-2).

NLP adversarial attacks work by word substitution:
  - Find words that strongly influence the model's prediction
  - Replace them with synonyms / similar-embedding words
  - Constraint: preserve grammar, keep semantic similarity high
  - Goal: flip the label while being imperceptible to a human reader

Run: conda activate llm-guard-env && python exercises/6.5.3-textattack-nlp.py
Note: First run downloads distilbert-sst2 (~250MB). Cached after that.
"""

print("=" * 60)
print("Exercise 6.5.3 — TextAttack NLP Adversarial Examples")
print("=" * 60)

import textattack
from textattack.models.wrappers import HuggingFaceModelWrapper
from textattack.attack_recipes import BAEGarg2019
from textattack.datasets import Dataset
from textattack import Attacker, AttackArgs
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
import torch
import warnings
warnings.filterwarnings("ignore")

# ── 1. Load the target model ──────────────────────────────────────────────────

MODEL_NAME = "distilbert-base-uncased-finetuned-sst-2-english"
print(f"\nLoading target model: {MODEL_NAME}")
print("(First run will download ~250MB — cached after that)\n")

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model     = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
model.eval()

# TextAttack model wrapper
wrapped_model = HuggingFaceModelWrapper(model, tokenizer)

# Also create a pipeline for easy baseline queries
clf = pipeline("sentiment-analysis", model=model, tokenizer=tokenizer,
               device=0 if torch.cuda.is_available() else -1)

# ── 2. Demo: baseline classification ─────────────────────────────────────────

print("─" * 50)
print("Baseline classification (no attack)")
print("─" * 50)

examples = [
    "This movie was absolutely fantastic and I loved every minute of it.",
    "The film is a dull, uninspired mess that wastes the entire cast.",
    "A masterpiece of modern cinema — deeply moving and visually stunning.",
    "Boring, predictable, and utterly forgettable. Avoid at all costs.",
]

for text in examples:
    result = clf(text)[0]
    print(f"  [{result['label']:8s} {result['score']:.3f}]  {text[:65]}")

# ── 3. TextFooler attack ──────────────────────────────────────────────────────

print("\n" + "─" * 50)
print("BAE Attack (Garg & Ramakrishnan, 2020)")
print("─" * 50)
print("Strategy: use BERT's masked language model to find word substitutions")
print("that fool the classifier while preserving grammaticality.\n")

# Build the attack
# BAEGarg2019 uses BERT masking — no TensorFlow/tensorflow-hub required.
# TextFoolerJin2019 uses UniversalSentenceEncoder which needs tensorflow-hub.
attack = BAEGarg2019.build(wrapped_model)

# Run on a small set of examples with known labels
# SST-2: 0 = NEGATIVE, 1 = POSITIVE
attack_dataset = Dataset([
    ("This movie was absolutely fantastic and I loved every minute of it.", 1),
    ("A masterpiece of modern cinema — deeply moving and visually stunning.", 1),
    ("The performances are stellar and the writing is sharp throughout.",  1),
    ("An uplifting and joyful experience that leaves you smiling.",        1),
    ("The film is a dull, uninspired mess that wastes the entire cast.",   0),
])

attack_args = AttackArgs(
    num_examples=5,
    disable_stdout=False,
    silent=False,
    log_to_txt=None,
    log_to_csv=None,
)

attacker = Attacker(attack, attack_dataset, attack_args)
results  = attacker.attack_dataset()

# ── 4. Analyse results ────────────────────────────────────────────────────────

print("\n" + "─" * 50)
print("Attack Results Summary")
print("─" * 50)

success_count = 0
total_words_changed = 0
total_samples = 0

for result in results:
    total_samples += 1
    original_text   = result.original_text()
    perturbed_text  = result.perturbed_text()
    original_label  = result.original_result.output
    perturbed_label = result.perturbed_result.output if hasattr(result, "perturbed_result") else None

    # Count word changes
    orig_words  = original_text.split()
    pert_words  = perturbed_text.split() if perturbed_text else orig_words
    n_changed   = sum(1 for a, b in zip(orig_words, pert_words) if a.lower() != b.lower())
    pct_changed = n_changed / max(len(orig_words), 1) * 100

    attack_succeeded = type(result).__name__ == "SuccessfulAttackResult"

    if attack_succeeded:
        success_count += 1
        total_words_changed += n_changed
        print(f"\n  ✅ ATTACK SUCCEEDED")
        print(f"  Original:  \"{original_text[:80]}\"")
        print(f"  Perturbed: \"{perturbed_text[:80]}\"")
        print(f"  Label flip: {original_label} → {perturbed_label}")
        print(f"  Words changed: {n_changed}/{len(orig_words)} ({pct_changed:.0f}%)")
    else:
        print(f"\n  ❌ Attack failed / skipped on: \"{original_text[:60]}...\"")

print("\n" + "─" * 50)
attack_rate = success_count / total_samples * 100 if total_samples > 0 else 0
avg_changes = total_words_changed / success_count if success_count > 0 else 0
print(f"Attack success rate: {success_count}/{total_samples} ({attack_rate:.0f}%)")
print(f"Avg words changed:   {avg_changes:.1f}")

print("\n" + "=" * 60)
print("KEY FINDING")
print("=" * 60)
print("  Changing 1-2 words to synonyms can flip a sentiment classifier's")
print("  label. The substitutions are semantically near-identical to humans")
print("  (loved → adored, fantastic → remarkable) but cross the model's")
print("  learned decision boundary.")
print("")
print("  Production relevance: content moderation, spam filters, toxicity")
print("  classifiers, and LLM input scanners are all NLP classifiers with")
print("  exploitable decision boundaries. An attacker who knows the classifier")
print("  is in use can craft inputs that evade it with minimal visible change.")
print("=" * 60)
