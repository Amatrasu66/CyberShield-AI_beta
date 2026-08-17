# ML Architecture

## Current Status
No trained AI/ML model is currently used for inference.

- The Email Detector currently runs a **deterministic heuristic analyzer**
  (`EmailService.ANALYZER_ID = "deterministic-heuristic-placeholder"`).
- The Log Analyzer currently runs a **deterministic rule-based analyzer**
  (`LogService.ANALYZER_ID = "deterministic-rule-based-placeholder"`).
- `backend/app/ml/phishing_detector.py` and `backend/app/ml/log_analyzer.py`
  are **placeholder inference modules**: `load_model` is a stub and `predict`
  returns defaults. No `.pkl` model is loaded at runtime; `GET /api/health`
  reports `"ml_models": "not_loaded"`.
- Scikit-learn integration is a planned direction, not implemented behavior.

## Planned Models
- Phishing Email Detector (Naive Bayes) — planned.
- Optional Log Analyzer (Random Forest) — planned.

## Planned Pipeline
Dataset -> Cleaning -> Training -> Evaluation -> Export (.pkl)

When implemented, the backend will load the exported `.pkl` models for inference.

## Rule
Do not document ML inference as implemented until the repository proves a
trained model is actually loaded and used.