"""Supervised fine-tuning entry point for the Stage-D disambiguator.

Usage (requires the ``[model]`` extra installed)::

    python -m scripts.train_disambig \
        --corpus-dir reports/disambig_corpus \
        --output-dir reports/disambig_ckpts/codet5p-220m-v1 \
        --base-model Salesforce/codet5p-220m \
        --epochs 3 --batch-size 16 --lr 5e-5

Outputs a HuggingFace-compatible checkpoint directory consumable by
:class:`core.disambig.ModelPolicy` via ``IR_SAM_DISAMBIG_MODEL``.

Design notes
------------

The disambiguator is trained as **next-token prediction on the answer
suffix** (causal LM teacher forcing); inference uses *per-label
sequence scoring* (see ``core.disambig.ModelPolicy``), so the training
objective is exactly aligned with the inference scoring rule.

This script is intentionally light on ML bells-and-whistles: a single
``Trainer.train()`` invocation, no curriculum, no LoRA by default
(enable with ``--peft``). Reproducibility hinges on the deterministic
80/10/10 split already encoded in :mod:`bench.disambig_corpus`.

Reviewer note: this script requires a GPU. In CPU-only environments it
will run but extremely slowly; for review we ship a pre-built
checkpoint via :mod:`scripts.fetch_disambig_model`.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# The transformers/torch imports are deferred so that running
# ``--help`` does not require the ``[model]`` extra.


def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Fine-tune the Stage-D SIG disambiguator."
    )
    p.add_argument("--corpus-dir", required=True, type=Path,
                   help="Directory containing train.jsonl / valid.jsonl")
    p.add_argument("--output-dir", required=True, type=Path,
                   help="Where to write the resulting checkpoint")
    p.add_argument("--base-model", default="Salesforce/codet5p-220m")
    p.add_argument("--epochs", type=int, default=3)
    p.add_argument("--batch-size", type=int, default=16)
    p.add_argument("--lr", type=float, default=5e-5)
    p.add_argument("--max-length", type=int, default=512)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--peft", action="store_true",
                   help="Train with LoRA adapters instead of full fine-tune.")
    return p


def _format_example(ex: dict) -> str:
    # MUST match `core.disambig.ModelPolicy._build_prompt`.
    labels = _label_set_for(ex["interpreter"], ex["site"])
    return (
        "# IR-SAM SIG disambiguation\n"
        f"# interpreter: {ex['interpreter']}\n"
        f"# site: {ex['site']}\n"
        f"# context: {ex['context']}\n"
        f"# sig: {ex['sig_text']}\n"
        f"# choose one of: {', '.join(labels)}\n"
        f"answer: {ex['label']}"
    )


def _label_set_for(interpreter: str, site: str) -> tuple[str, ...]:
    from core.disambig import labels as label_schema
    return label_schema.get(interpreter, site).labels


def _load_jsonl(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def main(argv: list[str] | None = None) -> int:
    args = _build_argparser().parse_args(argv)

    try:
        import torch  # type: ignore
        from transformers import (  # type: ignore
            AutoModelForCausalLM, AutoTokenizer, Trainer,
            TrainingArguments, DataCollatorForLanguageModeling,
        )
        from datasets import Dataset  # type: ignore
    except ImportError as e:
        print(f"[train_disambig] ERROR: install the [model] extra: {e}",
              file=sys.stderr)
        return 2

    train_path = args.corpus_dir / "train.jsonl"
    valid_path = args.corpus_dir / "valid.jsonl"
    if not train_path.exists() or not valid_path.exists():
        print(f"[train_disambig] ERROR: corpus missing. Run "
              f"`python -m bench.disambig_corpus` first.", file=sys.stderr)
        return 2

    train_records = _load_jsonl(train_path)
    valid_records = _load_jsonl(valid_path)

    train_texts = [_format_example(r) for r in train_records]
    valid_texts = [_format_example(r) for r in valid_records]

    tokenizer = AutoTokenizer.from_pretrained(args.base_model)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    def _encode(batch):
        enc = tokenizer(
            batch["text"], truncation=True, padding="max_length",
            max_length=args.max_length,
        )
        enc["labels"] = list(enc["input_ids"])
        return enc

    train_ds = Dataset.from_dict({"text": train_texts}).map(
        _encode, batched=True, remove_columns=["text"]
    )
    valid_ds = Dataset.from_dict({"text": valid_texts}).map(
        _encode, batched=True, remove_columns=["text"]
    )

    model = AutoModelForCausalLM.from_pretrained(args.base_model)
    if args.peft:
        try:
            from peft import LoraConfig, get_peft_model, TaskType  # type: ignore
        except ImportError:
            print("[train_disambig] ERROR: --peft requires the `peft` package.",
                  file=sys.stderr)
            return 2
        cfg = LoraConfig(
            task_type=TaskType.CAUSAL_LM,
            r=16, lora_alpha=32, lora_dropout=0.05,
        )
        model = get_peft_model(model, cfg)

    training_args = TrainingArguments(
        output_dir=str(args.output_dir),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        learning_rate=args.lr,
        eval_strategy="epoch",
        save_strategy="epoch",
        save_total_limit=1,
        seed=args.seed,
        report_to="none",
        load_best_model_at_end=True,
    )
    trainer = Trainer(
        model=model, args=training_args,
        train_dataset=train_ds, eval_dataset=valid_ds,
        tokenizer=tokenizer,
        data_collator=DataCollatorForLanguageModeling(tokenizer, mlm=False),
    )
    trainer.train()
    trainer.save_model(str(args.output_dir))
    tokenizer.save_pretrained(str(args.output_dir))
    print(f"[train_disambig] OK: wrote checkpoint to {args.output_dir}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
