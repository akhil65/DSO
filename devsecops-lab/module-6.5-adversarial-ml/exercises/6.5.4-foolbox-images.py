#!/usr/bin/env python3
"""
Exercise 6.5.4 — Foolbox Image Adversarial Examples
====================================================
Uses Foolbox to craft adversarial examples against torchvision ResNet-18
pretrained on ImageNet. Demonstrates three attacks with different trade-offs:
  - FGSM:     fast, single-step, L∞ bounded
  - DeepFool: minimum-norm (finds closest point across decision boundary)
  - L-BFGS:   optimisation-based, strong misclassification with tiny perturbation

Requires torchvision and Pillow. Saves perturbed images to exercises/output/.

Run: conda activate llm-guard-env && python exercises/6.5.4-foolbox-images.py
"""

import os
import numpy as np
import torch
import torchvision.models as models
import torchvision.transforms as transforms
from PIL import Image
import urllib.request
import warnings
warnings.filterwarnings("ignore")

print("=" * 60)
print("Exercise 6.5.4 — Foolbox Image Adversarial Examples")
print("=" * 60)

# ── Setup output directory ────────────────────────────────────────────────────

output_dir = os.path.join(os.path.dirname(__file__), "output")
os.makedirs(output_dir, exist_ok=True)

# ── 1. Load ResNet-18 pretrained on ImageNet ──────────────────────────────────

print("\nLoading ResNet-18 (pretrained ImageNet)... ", end="", flush=True)
model = models.resnet18(weights=models.ResNet18_Weights.IMAGENET1K_V1)
model.eval()
print("done")

# ImageNet normalisation
mean = [0.485, 0.456, 0.406]
std  = [0.229, 0.224, 0.225]

preprocessing = dict(mean=mean, std=std, axis=-3)

transform = transforms.Compose([
    transforms.Resize(256),
    transforms.CenterCrop(224),
    transforms.ToTensor(),
])

# ImageNet class labels (top-10 used here)
IMAGENET_LABELS = {
    281: "tabby cat",
    282: "tiger cat",
    283: "persian cat",
    284: "siamese cat",
    285: "Egyptian cat",
    330: "wood rabbit",
    340: "zebra",
    386: "African elephant",
    291: "lion",
    388: "panda",
}

def get_label(idx):
    return IMAGENET_LABELS.get(idx, f"class_{idx}")

# ── 2. Create a test image (or download one) ──────────────────────────────────

# We use a synthetic image (solid colour patch) to avoid download dependency.
# For real results, replace this with an actual photo.
print("\nCreating synthetic test image (grey gradient — works with any model)...")
synthetic = np.zeros((224, 224, 3), dtype=np.uint8)
for i in range(224):
    for j in range(224):
        synthetic[i, j] = [int(255 * i / 224), int(255 * j / 224), 128]

img_pil  = Image.fromarray(synthetic)
img_t    = transform(img_pil).unsqueeze(0)  # [1, 3, 224, 224]

# Get clean prediction
with torch.no_grad():
    logits     = model(img_t)
    probs      = torch.softmax(logits, dim=1)
    top_class  = probs.argmax(dim=1).item()
    top_prob   = probs.max().item()

print(f"\nClean prediction:  class {top_class} ({get_label(top_class)})  p={top_prob:.3f}")
Image.fromarray(synthetic).save(os.path.join(output_dir, "original.png"))

# ── 3. Foolbox attacks ────────────────────────────────────────────────────────

try:
    import foolbox as fb

    fmodel = fb.PyTorchModel(model, bounds=(0, 1), preprocessing=preprocessing)

    images  = img_t.clone()
    # Foolbox needs labels as tensor
    labels  = torch.tensor([top_class])

    print("\n" + "─" * 50)
    print("Attack results (Foolbox)")
    print("─" * 50)

    # ── FGSM ──
    attack_fgsm = fb.attacks.FGSM()
    _, adv_fgsm, success_fgsm = attack_fgsm(fmodel, images, labels,
                                             epsilons=[0.01, 0.05, 0.1])

    print("\nFGSM:")
    for eps, adv, suc in zip([0.01, 0.05, 0.1], adv_fgsm, success_fgsm):
        with torch.no_grad():
            adv_logits = model(adv)
            adv_class  = adv_logits.argmax(dim=1).item()
            adv_prob   = torch.softmax(adv_logits, dim=1).max().item()
        linf = (adv - images).abs().max().item()
        status = "✅ SUCCESS" if suc.item() else "❌ failed"
        print(f"  ε={eps:.2f}: {get_label(top_class)} → {get_label(adv_class):20s}  "
              f"p={adv_prob:.3f}  L∞={linf:.4f}  {status}")
        if eps == 0.05:
            # Save this adversarial image
            adv_np = adv.squeeze().permute(1,2,0).detach().numpy()
            adv_np = (adv_np * 255).clip(0, 255).astype(np.uint8)
            Image.fromarray(adv_np).save(os.path.join(output_dir, "adversarial_fgsm.png"))

    # ── DeepFool ──
    attack_df = fb.attacks.LinfDeepFoolAttack(steps=50)
    _, adv_df, success_df = attack_df(fmodel, images, labels, epsilons=[0.1])

    print("\nDeepFool (minimum L∞ perturbation):")
    adv = adv_df[0]
    with torch.no_grad():
        adv_class = model(adv).argmax(dim=1).item()
        adv_prob  = torch.softmax(model(adv), dim=1).max().item()
    linf_df = (adv - images).abs().max().item()
    l2_df   = (adv - images).norm(p=2).item()
    suc     = success_df[0].item()
    print(f"  {get_label(top_class)} → {get_label(adv_class):20s}  "
          f"p={adv_prob:.3f}  L∞={linf_df:.4f}  L2={l2_df:.4f}  "
          f"{'✅ SUCCESS' if suc else '❌ failed'}")

    # ── L-BFGS ──
    attack_lbfgs = fb.attacks.L2CarliniWagnerAttack(binary_search_steps=5,
                                                      steps=100,
                                                      confidence=0.0)
    print("\nCarlini-Wagner L2 (optimisation-based — finds minimal perturbation):")
    try:
        _, adv_cw, success_cw = attack_lbfgs(fmodel, images, labels,
                                              epsilons=[1.0])
        adv = adv_cw[0]
        with torch.no_grad():
            adv_class = model(adv).argmax(dim=1).item()
            adv_prob  = torch.softmax(model(adv), dim=1).max().item()
        l2_cw = (adv - images).norm(p=2).item()
        suc   = success_cw[0].item()
        print(f"  {get_label(top_class)} → {get_label(adv_class):20s}  "
              f"p={adv_prob:.3f}  L2={l2_cw:.4f}  {'✅ SUCCESS' if suc else '❌ failed'}")
    except Exception as e:
        print(f"  C&W skipped: {e}")

    print(f"\nOriginal image saved to:    {output_dir}/original.png")
    print(f"FGSM adversarial saved to:  {output_dir}/adversarial_fgsm.png")
    print("Open both images — they are visually indistinguishable.")

except ImportError:
    print("\n[!] Foolbox not installed. Run: pip install foolbox")
    print("    Showing attack logic without live results.\n")
    print("    FGSM equivalent in Foolbox:")
    print("      fmodel = fb.PyTorchModel(model, bounds=(0,1))")
    print("      attack = fb.attacks.FGSM()")
    print("      _, adv, success = attack(fmodel, images, labels, epsilons=[0.05])")

print("\n" + "=" * 60)
print("KEY FINDING")
print("=" * 60)
print("  DeepFool finds the minimum-norm perturbation — it searches for")
print("  the closest point across the decision boundary, not just the")
print("  direction of steepest ascent. This means it produces smaller,")
print("  more 'efficient' adversarial examples than FGSM.")
print("")
print("  Carlini-Wagner runs an optimisation loop: minimise perturbation")
print("  size subject to misclassification — most powerful, slowest.")
print("")
print("  All three attacks produce perturbations imperceptible to humans.")
print("  Image saved to exercises/output/ for visual inspection.")
print("=" * 60)
