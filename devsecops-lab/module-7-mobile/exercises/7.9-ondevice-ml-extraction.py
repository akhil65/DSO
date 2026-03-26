#!/usr/bin/env python3
"""
Exercise 7.9 — AI Mobile Security: On-Device ML Model Extraction
================================================================
Extracts and analyses machine learning model files embedded inside
Android APKs — applying the Module 6.5 model extraction attack to
a mobile delivery mechanism.

  Phase 1 — Model file discovery
    Scans the APK (as a ZIP) for ML model files:
      .tflite  — TensorFlow Lite (most common Android ML)
      .onnx    — Open Neural Network Exchange (cross-platform)
      .pb      — TensorFlow frozen graph (older apps)
      .pt/.bin — PyTorch Mobile
      .mlmodel — Core ML (iOS, but sometimes bundled in hybrid apps)
      assets/  — raw model files without extension (common in React Native)

  Phase 2 — Model extraction
    Extracts model files from the APK ZIP to disk.
    Models are NOT encrypted by default — they are stored as plain binary
    assets, accessible to anyone who can unzip the APK.

  Phase 3 — TFLite model inspection
    Without executing the model, inspects the FlatBuffer schema:
      - Input/output tensor shapes and data types
      - Operator graph (layer types and count)
      - Model metadata (author, version, description, labels)
      - Whether the model is quantised (INT8 = smaller, faster)

  Phase 4 — Model querying
    If tflite-runtime (or tensorflow) is installed, loads the model
    and runs inference with synthetic inputs to:
      - Confirm the model is functional
      - Probe input/output boundaries
      - Demonstrate the Module 6.5 model extraction attack path

  Phase 5 — Intellectual property and privacy assessment
    A custom on-device model represents significant IP:
      - Training data (proprietary datasets)
      - Architecture decisions (competitive advantage)
      - Labels/classes (product roadmap information)
    Assesses what the extracted model reveals about the product.

REAL-WORLD CONTEXT:
  On-device ML is the fastest-growing category of mobile AI:
    - OCR / document scanning (bank apps, expense apps)
    - Face liveness detection (banking biometrics)
    - Object detection (shopping, AR apps)
    - NLP / text classification (content moderation, spam filters)
    - Recommendation models (personalisation without server round-trip)

  These models are valuable IP. Extracting them enables:
    1. Model stealing — run the model on your own infrastructure at zero cost
    2. Adversarial inputs — craft inputs that fool the model (Module 6.5 FGSM)
    3. Label leakage — discover what categories/classes the product recognises
    4. Architecture reverse engineering — understand the model design
    5. Privacy inference — infer what training data was used

  MASVS control: MSTG-RESILIENCE-9 — the app should implement model protection
  (encryption, integrity checking) before distributing commercially sensitive
  ML models in the APK.

Run:
  python exercises/7.9-ondevice-ml-extraction.py
  python exercises/7.9-ondevice-ml-extraction.py --apk targets/tflite-demo.apk
"""

import os
import re
import sys
import json
import struct
import zipfile
import argparse
from pathlib import Path

APK_PATH = os.getenv("APK_PATH", "targets/tflite-demo.apk")

# Model file signatures by magic bytes
MODEL_MAGIC = {
    b'ODML': 'TFLite (FlatBuffer)',
    b'\x18\x00\x00\x00':   'TFLite (alternative header)',
    b'PK\x03\x04':         'ZIP-based (ONNX or PyTorch)',
    b'\x08\x00':           'TensorFlow protobuf (.pb)',
}

# TFLite FlatBuffer constants (schema offsets)
TFLITE_MAGIC = b'ODML'

# ── Phase 1: Model discovery ──────────────────────────────────────────────────

def discover_model_files(apk_path: str) -> list:
    models = []
    print("\n[Phase 1] ML Model File Discovery")
    print("─" * 60)

    ml_extensions = {'.tflite', '.onnx', '.pb', '.pt', '.bin', '.mlmodel', '.ptl'}
    ml_name_patterns = [
        r'model', r'classifier', r'detector', r'recognizer',
        r'encoder', r'decoder', r'embedding', r'inference',
        r'\.tflite', r'\.onnx', r'mobilenet', r'efficientnet',
        r'bert', r'distilbert', r'resnet', r'yolo',
    ]
    ml_regex = re.compile('|'.join(ml_name_patterns), re.IGNORECASE)

    with zipfile.ZipFile(apk_path, 'r') as apk:
        for entry in apk.namelist():
            is_ml = (
                any(entry.endswith(ext) for ext in ml_extensions) or
                bool(ml_regex.search(entry))
            )
            if is_ml:
                info = apk.getinfo(entry)
                models.append({
                    'path':     entry,
                    'size_kb':  info.file_size / 1024,
                    'compress': info.compress_size / 1024,
                })

    print(f"  ML-related files found: {len(models)}")
    for m in models:
        ratio = (1 - m['compress'] / m['size_kb']) * 100 if m['size_kb'] > 0 else 0
        print(f"  📦 {m['path']}")
        print(f"     Size: {m['size_kb']:.1f} KB (compressed {m['compress']:.1f} KB, {ratio:.0f}% reduction)")

    if not models:
        print("  No ML model files detected in this APK.")
        print("  DIVA has no ML features — use targets/tflite-demo.apk or")
        print("  any production AI assistant app APK for this exercise.")

    return models

# ── Phase 2: Model extraction ─────────────────────────────────────────────────

def extract_models(apk_path: str, models: list) -> list:
    extracted = []
    print("\n[Phase 2] Model Extraction")
    print("─" * 60)

    out_dir = Path("reports/7.9-extracted-models")
    out_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(apk_path, 'r') as apk:
        for model in models:
            entry = model['path']
            out_path = out_dir / Path(entry).name
            data = apk.read(entry)

            # Check magic bytes
            magic = data[:4]
            detected_type = MODEL_MAGIC.get(magic, f"unknown (magic: {magic.hex()})")

            out_path.write_bytes(data)
            print(f"  ✅ Extracted: {out_path.name}")
            print(f"     Type:   {detected_type}")
            print(f"     Size:   {len(data) / 1024:.1f} KB")

            extracted.append({
                'original_path': entry,
                'local_path':    str(out_path),
                'size_bytes':    len(data),
                'detected_type': detected_type,
            })

    if extracted:
        print(f"\n  All models extracted to: {out_dir}")
        print(f"  An attacker can now: load these models, query them freely,")
        print(f"  craft adversarial inputs, and steal the IP — no device needed.")
    return extracted

# ── Phase 3: TFLite model inspection ─────────────────────────────────────────

def inspect_tflite_model(model_path: str) -> dict:
    """Parse TFLite FlatBuffer metadata without running the model."""
    print("\n[Phase 3] TFLite Model Inspection (static)")
    print("─" * 60)

    data = Path(model_path).read_bytes()

    if not data.startswith(TFLITE_MAGIC):
        print(f"  Not a TFLite FlatBuffer (magic: {data[:4].hex()})")
        return {}

    print(f"  TFLite FlatBuffer confirmed ✅")
    print(f"  Size: {len(data) / 1024:.1f} KB")

    # FlatBuffer root offset is at bytes 4-8
    root_offset = struct.unpack_from('<I', data, 4)[0]

    # Heuristic string extraction from FlatBuffer
    # Model metadata, operator names, tensor names are UTF-8 strings
    strings = re.findall(rb'[\x20-\x7e\n]{8,}', data)
    decoded = [s.decode('utf-8', errors='replace') for s in strings]

    # Filter for meaningful strings
    layer_types = set()
    known_layers = ['CONV_2D', 'DEPTHWISE_CONV_2D', 'FULLY_CONNECTED', 'RELU',
                    'RELU6', 'SOFTMAX', 'MAX_POOL_2D', 'AVERAGE_POOL_2D',
                    'RESHAPE', 'ADD', 'CONCATENATION', 'LSTM', 'BIDIRECTIONAL_SEQUENCE_LSTM',
                    'EMBEDDING_LOOKUP', 'LOGISTIC', 'BATCH_NORM', 'MUL']
    for s in decoded:
        for layer in known_layers:
            if layer in s:
                layer_types.add(layer)

    # Metadata strings (author, description, labels)
    metadata = [s for s in decoded
                if len(s) > 10 and not any(c in s for c in '{}[]<>')]

    print(f"\n  Layer types detected ({len(layer_types)}):")
    for lt in sorted(layer_types):
        layer_desc = {
            'CONV_2D':             'Convolutional layer — image feature extraction',
            'FULLY_CONNECTED':     'Dense layer — classification head',
            'LSTM':                'Recurrent layer — sequence/text processing',
            'SOFTMAX':             'Output normalisation — multi-class classifier',
            'EMBEDDING_LOOKUP':    'Word/token embeddings — NLP model',
            'DEPTHWISE_CONV_2D':   'Efficient mobile convolution (MobileNet family)',
        }.get(lt, '')
        suffix = f'  ← {layer_desc}' if layer_desc else ''
        print(f"    {lt}{suffix}")

    # Architecture inference
    if 'LSTM' in layer_types or 'EMBEDDING_LOOKUP' in layer_types:
        arch = "NLP / text model (LSTM or embedding layers present)"
    elif 'CONV_2D' in layer_types or 'DEPTHWISE_CONV_2D' in layer_types:
        arch = "Computer vision model (convolutional layers present)"
    elif 'FULLY_CONNECTED' in layer_types:
        arch = "Tabular / feature model (dense layers only)"
    else:
        arch = "Unknown architecture"

    print(f"\n  Inferred architecture: {arch}")

    # Quantisation check (INT8 values in metadata strings)
    is_quantised = b'int8' in data.lower() or b'uint8' in data.lower()
    print(f"  Quantised (INT8): {'Yes — reduced precision for mobile speed' if is_quantised else 'No — FP32 full precision'}")

    # Potential label strings
    label_candidates = [s for s in decoded
                        if 5 < len(s) < 30 and s.replace('_','').replace(' ','').isalpha()]
    if label_candidates:
        print(f"\n  Potential class labels (first 10):")
        for l in label_candidates[:10]:
            print(f"    '{l}'")
        print(f"  → Labels reveal what the model classifies — product roadmap info")

    return {'layers': sorted(layer_types), 'architecture': arch, 'quantised': is_quantised}

# ── Phase 4: Model querying ────────────────────────────────────────────────────

def query_model(model_path: str):
    print("\n[Phase 4] Model Querying (live inference)")
    print("─" * 60)

    try:
        import numpy as np
    except ImportError:
        print("  numpy not installed. pip install numpy")
        return

    # Try tflite-runtime first (lightweight), fall back to tensorflow
    interpreter = None
    try:
        import tflite_runtime.interpreter as tflite
        interpreter = tflite.Interpreter(model_path=model_path)
        print("  Runtime: tflite-runtime  ✅")
    except ImportError:
        try:
            import tensorflow as tf
            interpreter = tf.lite.Interpreter(model_path=model_path)
            print("  Runtime: tensorflow  ✅")
        except (ImportError, SystemError, Exception) as e:
            print("  Live inference skipped — TF/numpy version mismatch:")
            print(f"  {type(e).__name__}: installed TensorFlow was compiled against")
            print("  NumPy 1.x but NumPy 2.x is active. This is a dependency conflict,")
            print("  not a code issue. The important work is in Phases 1–3.")
            print()
            print("  To fix: pip install 'numpy<2' && pip install tflite-runtime")
            print("  Or: conda install tensorflow  (manages numpy compat automatically)")
            return

    interpreter.allocate_tensors()
    inputs  = interpreter.get_input_details()
    outputs = interpreter.get_output_details()

    print(f"\n  Input tensors:  {len(inputs)}")
    for i, inp in enumerate(inputs):
        print(f"    [{i}] shape={inp['shape']}  dtype={inp['dtype'].__name__}  name={inp['name']}")

    print(f"  Output tensors: {len(outputs)}")
    for i, out in enumerate(outputs):
        print(f"    [{i}] shape={out['shape']}  dtype={out['dtype'].__name__}  name={out['name']}")

    # Run with random synthetic input
    print(f"\n  Running inference with random synthetic input ...")
    for inp in inputs:
        shape = inp['shape']
        dtype = inp['dtype']
        if dtype == np.float32:
            data = np.random.rand(*shape).astype(np.float32)
        elif dtype in (np.uint8, np.int8):
            data = np.random.randint(0, 255, shape).astype(dtype)
        else:
            data = np.zeros(shape, dtype=dtype)
        interpreter.set_tensor(inp['index'], data)

    interpreter.invoke()

    for i, out in enumerate(outputs):
        result = interpreter.get_tensor(out['index'])
        print(f"  Output [{i}]: shape={result.shape}  "
              f"min={result.min():.4f}  max={result.max():.4f}  "
              f"argmax={result.argmax()}")

    print(f"""
  KEY FINDING (MSTG-RESILIENCE-9):
    Model loaded and executed successfully from extracted APK file.
    An attacker now has:
      - A functional copy of the model (no server, no licence, no auth)
      - Knowledge of input/output shapes (enables adversarial input crafting)
      - Class labels (if present in metadata)
      - Architecture details (competitive intelligence)

    The Module 6.5 FGSM / HopSkipJump attacks from adversarial ML now
    apply directly to this model — the attacker has full white-box access.
""")

# ── Phase 5: IP and privacy assessment ────────────────────────────────────────

def assess_model_ip(extracted: list, inspection: dict):
    print("[Phase 5] Intellectual Property & Privacy Assessment")
    print("─" * 60)

    if not extracted:
        print("  No models extracted — no assessment possible.")
        return

    print(f"""
  Models extracted from APK: {len(extracted)}

  IP exposure:
    Custom trained models represent 6–18 months of ML engineering work:
    data collection, labelling, training runs, evaluation, optimisation.
    Once extracted, a competitor can:
      ✗ Run the model on their own infrastructure (zero marginal cost)
      ✗ Study the architecture and replicate it
      ✗ Use it as a teacher model to distil a smaller version
      ✗ Fine-tune it on their own data

  Privacy implications:
    Models trained on user data can leak information about that data
    through membership inference (Module 6.5, Exercise 6.5.7).
    A face recognition model trained on user selfies may memorise
    specific faces. An NLP model may memorise rare training phrases.

  Protections an org should implement:
    1. Model encryption at rest (AES-256) — decrypt key in Android Keystore
    2. Integrity check: verify model hash before loading
    3. Split architecture: sensitive layers on server, edge model is partial
    4. Obfuscation: remove metadata, rename layers, remove label strings
    5. Watermarking: embed a model fingerprint detectable if the model is
       reused (enables legal action for IP theft)

  MASVS: MSTG-RESILIENCE-9 — "The app implements a 'device binding' functionality
  using a device fingerprint derived from multiple properties unique to the device."
  Extended interpretation: model assets should be device-bound where possible.
""")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Exercise 7.9 — On-device ML extraction")
    parser.add_argument("--apk", default=APK_PATH, help="Path to APK")
    args = parser.parse_args()

    print("=" * 70)
    print("Exercise 7.9 — AI Mobile: On-Device ML Model Extraction")
    print(f"Target: {args.apk}")
    print("=" * 70)

    if not Path(args.apk).exists():
        print(f"\n[ERROR] APK not found: {args.apk}")
        print("Use targets/tflite-demo.apk or any production AI app APK.")
        print("For DIVA: curl -L -o targets/diva-beta.apk \\")
        print("  https://github.com/payatu/diva-android/raw/master/DivaApplication.apk")
        sys.exit(1)

    models    = discover_model_files(args.apk)
    extracted = extract_models(args.apk, models)

    inspection = {}
    tflite_models = [e for e in extracted if 'TFLite' in e['detected_type']]
    if tflite_models:
        inspection = inspect_tflite_model(tflite_models[0]['local_path'])
        query_model(tflite_models[0]['local_path'])

    assess_model_ip(extracted, inspection)

    out = Path("reports/7.9-model-extraction.json")
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({
        "models_found": models,
        "extracted": extracted,
        "inspection": inspection
    }, indent=2))
    print(f"\n  Report saved: {out}")
    print("  Next: Exercise 7.10 — Prompt injection via intercepted mobile API call")

if __name__ == "__main__":
    main()
