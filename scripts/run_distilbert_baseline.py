#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cti_pipeline.distilbert_baseline import (
    DistilBertBaselineConfig,
    build_simple_ddos_incident_texts,
    build_uwf24_incident_texts,
    evaluate_predictions,
    find_ambiguous_texts,
    get_device,
    load_simple_ddos,
    load_uwf24,
    make_dataloaders,
    predict_model,
    prepare_training_frame,
    set_reproducibility,
    split_training_frame,
    token_occlusion_importance,
    train_model,
)


def parse_args():
    parser = argparse.ArgumentParser(description="Run DistilBERT baseline for intermediate CTI incident classification.")
    parser.add_argument("--task", choices=["uwf24_tactic", "uwf24_binary", "bccc_binary", "sdn_syn_binary"], default="uwf24_tactic")
    parser.add_argument("--dataset-root", default="datasets", help="Root containing BCCC/SDN datasets.")
    parser.add_argument("--uwf24-root", default="datasets/UWF-ZeekData24-csv", help="Root containing UWF-ZeekData24 CSV folders.")
    parser.add_argument("--output-dir", default="distilbert_outputs")
    parser.add_argument("--model-name", default="distilbert-base-uncased")
    parser.add_argument("--max-length", type=int, default=256)
    parser.add_argument("--max-incidents-per-class", type=int, default=3000)
    parser.add_argument("--min-samples-per-class", type=int, default=2)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--epochs", type=int, default=2)
    parser.add_argument("--learning-rate", type=float, default=2e-5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--limit-files", type=int, default=None, help="Limit UWF24 files for quick tests.")
    parser.add_argument("--nrows-per-file", type=int, default=None, help="Limit UWF24 rows per file for quick tests.")
    parser.add_argument("--include-label-hints", action="store_true", help="Include label hints in text. Use only for leakage/upper-bound tests.")
    parser.add_argument("--keep-ambiguous-texts", action="store_true", help="Keep identical abstractions that map to multiple labels.")
    parser.add_argument("--no-class-weights", action="store_true")
    parser.add_argument("--skip-token-importance", action="store_true")
    return parser.parse_args()


def load_task_data(args, config):
    dataset_root = Path(args.dataset_root)
    if args.task in {"uwf24_tactic", "uwf24_binary"}:
        raw_df = load_uwf24(Path(args.uwf24_root), limit_files=args.limit_files, nrows_per_file=args.nrows_per_file)
        return raw_df, build_uwf24_incident_texts(
            raw_df,
            task=args.task,
            include_label_hints=config.include_label_hints,
        )
    if args.task == "bccc_binary":
        raw_df = load_simple_ddos(dataset_root / "BCCC-Cpacket-Cloud-DDoS-2024.csv")
        return raw_df, build_simple_ddos_incident_texts(raw_df, args.task)
    if args.task == "sdn_syn_binary":
        raw_df = load_simple_ddos(
            dataset_root / "SDN-TCP-SYN ATTACK-DDOS-CLEAN.csv",
            sep=";",
            timestamp_format="%d/%m/%y %H.%M",
        )
        return raw_df, build_simple_ddos_incident_texts(raw_df, args.task)
    raise ValueError(f"Unsupported task: {args.task}")


def main():
    args = parse_args()
    output_dir = Path(args.output_dir)
    table_dir = output_dir / "tables"
    model_dir = output_dir / "models" / args.task
    table_dir.mkdir(parents=True, exist_ok=True)
    model_dir.mkdir(parents=True, exist_ok=True)

    max_per_class = args.max_incidents_per_class if args.max_incidents_per_class > 0 else None
    config = DistilBertBaselineConfig(
        task=args.task,
        model_name=args.model_name,
        max_length=args.max_length,
        max_incidents_per_class=max_per_class,
        min_samples_per_class=args.min_samples_per_class,
        batch_size=args.batch_size,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
        seed=args.seed,
        include_label_hints=args.include_label_hints,
        drop_ambiguous_texts=not args.keep_ambiguous_texts,
        use_class_weights=not args.no_class_weights,
    )
    set_reproducibility(config.seed)

    raw_df, dataset_df = load_task_data(args, config)
    ambiguous_df = find_ambiguous_texts(dataset_df)
    if not ambiguous_df.empty:
        ambiguous_df.to_csv(table_dir / f"{args.task}_ambiguous_abstractions.csv", index=False)

    training_df, id2label, label2id = prepare_training_frame(dataset_df, config)
    train_df, test_df = split_training_frame(training_df, config)
    training_df.to_csv(table_dir / f"{args.task}_training_abstractions.csv", index=False)

    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    device = get_device()
    label_names = [id2label[i] for i in sorted(id2label)]
    tokenizer = AutoTokenizer.from_pretrained(config.model_name)
    model = AutoModelForSequenceClassification.from_pretrained(
        config.model_name,
        num_labels=len(label_names),
        id2label=id2label,
        label2id=label2id,
    )
    model.to(device)
    train_loader, test_loader = make_dataloaders(train_df, test_df, tokenizer, config)
    losses = train_model(model, train_loader, train_df, label_names, config, device)
    y_true, y_pred, y_prob = predict_model(model, test_loader, device)
    result, metrics_df = evaluate_predictions(y_true, y_pred, label_names)
    metrics_df.insert(0, "task", args.task)
    metrics_df.insert(1, "accuracy", result["accuracy"])
    metrics_df.insert(2, "macro_f1", result["macro_f1"])
    metrics_df.to_csv(table_dir / f"{args.task}_distilbert_metrics.csv", index=False)

    predictions = test_df.copy().reset_index(drop=True)
    predictions["true_label"] = [id2label[int(item)] for item in y_true]
    predictions["pred_label"] = [id2label[int(item)] for item in y_pred]
    predictions["correct"] = predictions["true_label"] == predictions["pred_label"]
    predictions["confidence"] = y_prob.max(axis=1)
    predictions.to_csv(table_dir / f"{args.task}_distilbert_predictions.csv", index=False)

    importance_path = None
    if not args.skip_token_importance and len(predictions):
        sample_idx = int(predictions["confidence"].values.argmax())
        sample_text = predictions.iloc[sample_idx]["text"]
        sample_target = label2id[predictions.iloc[sample_idx]["pred_label"]]
        importance_df = token_occlusion_importance(model, tokenizer, sample_text, device, target_label_id=sample_target)
        importance_path = table_dir / f"{args.task}_token_importance_example.csv"
        importance_df.to_csv(importance_path, index=False)

    model.save_pretrained(model_dir)
    tokenizer.save_pretrained(model_dir)

    manifest = {
        "config": config.to_dict(),
        "device": str(device),
        "raw_rows": int(len(raw_df)),
        "incident_text_rows": int(len(dataset_df)),
        "training_rows": int(len(training_df)),
        "train_rows": int(len(train_df)),
        "test_rows": int(len(test_df)),
        "labels": label_names,
        "train_losses": losses,
        "metrics": result,
        "metrics_csv": str(table_dir / f"{args.task}_distilbert_metrics.csv"),
        "predictions_csv": str(table_dir / f"{args.task}_distilbert_predictions.csv"),
        "ambiguous_abstractions_csv": str(table_dir / f"{args.task}_ambiguous_abstractions.csv") if not ambiguous_df.empty else None,
        "token_importance_csv": str(importance_path) if importance_path else None,
        "model_dir": str(model_dir),
    }
    (output_dir / f"{args.task}_distilbert_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({k: manifest[k] for k in ["raw_rows", "incident_text_rows", "training_rows", "train_rows", "test_rows", "labels"]}, indent=2))
    print(f"Accuracy: {result['accuracy']:.4f}")
    print(f"Macro-F1: {result['macro_f1']:.4f}")
    print(result["classification_report"])


if __name__ == "__main__":
    main()
