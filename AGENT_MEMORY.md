# Agent Memory

## Project Identity

- Repository: `humanized-cti-llm`
- Remote: `https://github.com/aquarink/humanized-cti-llm.git`
- Research theme: explainable, LLM-ready CTI report generation from network telemetry using incident-level abstraction and MITRE ATT&CK alignment.

## Current Methodological Position

This project is not primarily an intrusion detection model. The main contribution is a pipeline that transforms network telemetry into analyst-readable CTI reports:

1. Network telemetry ingestion and preprocessing.
2. Incident-level abstraction.
3. Threat knowledge alignment with MITRE ATT&CK.
4. Explainable evidence traceability.
5. LLM-ready CTI report generation.
6. Qualitative narrative evaluation.

Traditional metrics such as accuracy, precision, recall, F1-score, and confusion matrix are used for intermediate components only, especially security-relevance filtering and DistilBERT-based incident classification.

## Completed Work

- Initialized git repository and pushed to GitHub.
- Added `.gitignore` so datasets, PDFs, `.DS_Store`, local secrets, and cache files are not committed.
- Added core CTI pipeline under `src/cti_pipeline/`:
  - `loaders.py`
  - `abstraction.py`
  - `threat_mapping.py`
  - `reporting.py`
  - `evaluation.py`
  - `metrics.py`
  - `xai.py`
  - `visualization.py`
- Added CLI scripts:
  - `scripts/generate_cti_reports.py`
  - `scripts/run_journal_experiments.py`
  - `scripts/run_distilbert_baseline.py`
- Added notebook generators:
  - `scripts/create_full_experiment_notebook.py`
  - `scripts/create_distilbert_notebook.py`
- Added notebooks:
  - `notebooks/full_cti_experiment.ipynb`
  - `notebooks/full_cti_experiment_DistilBERT.ipynb`
- Added paper assets:
  - `paper_assets/equations_and_method_notes.md`
  - `paper_assets/baseline_and_ablation_plan.md`
  - `paper_assets/figure_captions.md`
  - dataset/metrics/XAI CSV outputs
  - SVG figures
- Added non-notebook DistilBERT baseline module:
  - `src/cti_pipeline/distilbert_baseline.py`

## DistilBERT Baseline Status

DistilBERT is implemented as an intermediate classification baseline, not as a CTI report generator.

Supported tasks:

- `uwf24_tactic`
- `uwf24_binary`
- `bccc_binary`
- `sdn_syn_binary`

Important safeguards:

- `include_label_hints` defaults to false to avoid label leakage.
- `drop_ambiguous_texts` defaults to true to remove identical abstractions with conflicting labels.
- `use_class_weights` defaults to true to reduce class imbalance impact.
- Macro-F1 should be prioritized over accuracy for imbalanced tactic classification.

Example CLI:

```bash
python3 scripts/run_distilbert_baseline.py \
  --task uwf24_tactic \
  --uwf24-root datasets/UWF-ZeekData24-csv \
  --output-dir distilbert_outputs \
  --epochs 2
```

For cloud Jupyter, use:

```bash
python3 scripts/run_distilbert_baseline.py \
  --task uwf24_tactic \
  --uwf24-root ~/cti_project/dataset/UWF-ZeekData24-csv \
  --dataset-root ~/datasets \
  --output-dir ~/cti_project/distilbert_outputs
```

## Observed DistilBERT Result From User Notebook Run

Initial user run on `uwf24_tactic` produced:

- Accuracy: `0.8879`
- Macro average F1: about `0.61`
- Strong classes:
  - `Credential Access`
  - `Reconnaissance`
  - `Defense Evasion`
- Weak/failed classes:
  - `Persistence`
  - `Privilege Escalation`

Interpretation:

- Accuracy is not sufficient because the dataset is imbalanced.
- `Persistence` and `Privilege Escalation` appear hard to separate from telemetry abstraction alone and were often predicted as `Initial Access`.
- This supports a research argument that ATT&CK mapping from network-only telemetry can be ambiguous and needs explicit evidence traceability.

## Files Intentionally Not Tracked

- `datasets/`
- `Pebri___CTI.pdf`
- `.DS_Store`
- `outputs_bccc_sample/`

Do not add dataset files or the PDF unless the user explicitly changes this policy.

## Remaining Work

- Run the updated DistilBERT notebook/CLI again after the no-label-leakage and ambiguity-control changes.
- Add final paper tables after full cloud experiments are complete.
- Add analyst-authored CTI report examples for qualitative baseline comparison.
- Add LLM-generated reports using an API key, then compare:
  - template-only report
  - LLM without MITRE
  - LLM with MITRE
  - analyst-authored report
- Consider richer XAI after the baseline is stable:
  - LIME
  - SHAP
  - attention/token attribution analysis

## Collaboration Advice For Future Agents

- Keep code changes in reusable project modules first; notebooks should be interfaces or generated artifacts.
- Commit and push after every meaningful change.
- Do not commit raw datasets or PDFs.
- Treat DistilBERT results as intermediate classification evidence, not final CTI narrative evaluation.
- Avoid overclaiming accuracy. Report macro-F1 and per-class F1 for imbalanced tasks.
- Keep final CTI narrative evaluation centered on clarity, actionability, analyst alignment, unsupported claims, and traceability.
