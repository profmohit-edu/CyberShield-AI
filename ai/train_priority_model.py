"""Train the bounded CyberShield action-priority softmax model reproducibly."""

from __future__ import annotations

import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parent
data = json.loads((ROOT / "training-data.json").read_text(encoding="utf-8"))
features = data["feature_names"]
classes = data["classes"]
rows = data["examples"]

weights = [[0.0 for _ in features] for _ in classes]
bias = [0.0 for _ in classes]
learning_rate = 0.12
l2_penalty = 0.002
steps = 7000

for _ in range(steps):
    weight_gradient = [[0.0 for _ in features] for _ in classes]
    bias_gradient = [0.0 for _ in classes]
    for row in rows:
        values = row["x"]
        target = classes.index(row["y"])
        logits = [
            bias[class_index]
            + sum(
                weight * value
                for weight, value in zip(weights[class_index], values, strict=True)
            )
            for class_index in range(len(classes))
        ]
        peak = max(logits)
        exponentials = [math.exp(value - peak) for value in logits]
        total = sum(exponentials)
        probabilities = [value / total for value in exponentials]
        for class_index in range(len(classes)):
            error = probabilities[class_index] - (1.0 if class_index == target else 0.0)
            bias_gradient[class_index] += error
            for feature_index, value in enumerate(values):
                weight_gradient[class_index][feature_index] += error * value
    sample_count = len(rows)
    for class_index in range(len(classes)):
        bias[class_index] -= learning_rate * bias_gradient[class_index] / sample_count
        for feature_index in range(len(features)):
            weights[class_index][feature_index] -= learning_rate * (
                weight_gradient[class_index][feature_index] / sample_count
                + l2_penalty * weights[class_index][feature_index]
            )

model = {
    "model_type": "multinomial_logistic_regression",
    "version": "1.0.0",
    "classes": classes,
    "feature_names": features,
    "weights": [[round(value, 8) for value in row] for row in weights],
    "bias": [round(value, 8) for value in bias],
    "training_examples": len(rows),
    "training_steps": steps,
    "training_data": "ai/training-data.json",
    "scope": "Bounded evidence-priority triage; findings remain deterministic.",
}
(ROOT / "priority-model.json").write_text(
    json.dumps(model, indent=2) + "\n",
    encoding="utf-8",
)
