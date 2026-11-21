#!/usr/bin/env python3
"""Evaluate the frozen 160-observation final campaign, without running analyzers."""

import argparse
from collections import Counter
import csv
import hashlib
from itertools import combinations, product
import json
import math
import os
from pathlib import Path
import platform
import shutil
import statistics
import sys
import tempfile

import numpy as np

if __package__:
    from . import extract, run_llm, static_baseline
    from . import freeze as input_freeze
else:
    import extract
    import run_llm
    import static_baseline
    import freeze as input_freeze


PROJECT_ROOT = Path(__file__).resolve().parents[1]
METHODS = ("static", "llm_majority")
AGREEMENT_UNCERTAIN = "uncertain_due_to_insufficient_agreement"
UNAVAILABLE = "unavailable"
ABSTENTIONS = {"uncertain", AGREEMENT_UNCERTAIN}
VULNERABLE = {"vulnerable_CWE-121", "vulnerable_CWE-122"}
DIMENSIONS = {"optimization": ("O0", "O2"), "symbols": ("retained", "stripped"),
              "cwe": ("CWE-121", "CWE-122"), "variant": ("vulnerable", "fixed"),
              "cohort": ("original", "extension"), "volatile_destination": ("no", "yes")}
COUNTS = ("n", "correct", "incorrect", "abstain", "unavailable", "tp", "tn", "fp", "fn",
          "tn_from_abstain", "tn_from_unavailable", "fn_from_abstain", "fn_from_unavailable",
          "wrong_cwe_alerts")
RATES = ("correct_rate", "coverage", "abstention_rate", "unavailability_rate", "selective_accuracy",
         "accuracy", "balanced_accuracy", "precision", "recall", "f1", "fpr", "fnr")
TABLE_FIELDS = ("kind", "method", "group", "level", "left", "right", "metric", "estimate",
                "ci_low", "ci_high", "bootstrap_defined", "bootstrap_total", "n", "n_pairs",
                "correct", "incorrect", "abstain", "unavailable", "coverage", "selective_accuracy")
ARTIFACTS = {"summary.csv", "subgroups.csv", "stability.csv", "report.md", "release_manifest.json",
             "diagnostics.json", "exploratory.md",
             "figures/coverage_accuracy.png", "figures/recall_fpr.png", "figures/treatment_accuracy.png"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path):
    require(path.is_file() and path.stat().st_size > 0, f"Missing or empty input: {path}")
    return run_llm.strict_json(path.read_text(encoding="utf-8"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def project_file(name):
    require(isinstance(name, str), "Expected a project-relative filename")
    path = Path(name)
    require(not path.is_absolute() and ".." not in path.parts and name == path.as_posix(),
            f"Unsafe project path: {name}")
    result = PROJECT_ROOT / path
    require(result.resolve().is_relative_to(PROJECT_ROOT.resolve())
            and result.is_file() and not result.is_symlink(), f"Missing or external input: {name}")
    return result


def load_config():
    config = read_json(PROJECT_ROOT / "config.json")
    evaluation = config["evaluation"]
    require(type(evaluation["bootstrap_repetitions"]) is int and evaluation["bootstrap_repetitions"] == 10000,
            "The plan requires 10,000 bootstrap replicates")
    require(type(evaluation["bootstrap_seed"]) is int and evaluation["bootstrap_seed"] >= 0,
            "Invalid bootstrap seed")
    threshold = evaluation["confidence_threshold"]
    require(type(threshold) in (float, int) and math.isfinite(threshold) and 0 <= threshold <= 1,
            "Invalid high-confidence threshold")
    llm = config["llm"]
    require(type(llm["repetitions"]) is int and llm["repetitions"] == 3,
            "Three configured LLM repetitions are required")
    require(isinstance(llm["seeds"], list) and len(llm["seeds"]) == 3
            and all(type(seed) is int and 0 <= seed < 2**32 - 1 for seed in llm["seeds"])
            and len(set(llm["seeds"])) == 3, "Invalid fixed LLM seeds")
    require(type(llm["schedule_seed"]) is int, "Invalid LLM schedule seed")
    return config


def load_truth():
    path = PROJECT_ROOT / "data/private/observations.csv"
    require(path.is_file() and path.stat().st_size, f"Missing or empty final truth table: {path}")
    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        require(reader.fieldnames and len(reader.fieldnames) == len(extract.OBSERVATION_FIELDS)
                and set(reader.fieldnames) == extract.OBSERVATION_FIELDS, "Invalid truth table columns")
        rows = list(reader)
    require(len(rows) == 160 and all(set(row) == extract.OBSERVATION_FIELDS and all(row.values()) for row in rows),
            "Final truth requires exactly 160 complete observations")
    require({row["observation_id"] for row in rows} == {f"r{i:04d}" for i in range(1, 161)},
            "Final observation IDs must be unique r0001 through r0160")
    with project_file("corpus/manifest.csv").open(newline="", encoding="utf-8") as stream:
        manifest = list(csv.DictReader(stream))
    require(len(manifest) == 22 and len({row["pair_id"] for row in manifest}) == 22,
            "Manifest requires 22 distinct pairs: two pilot and twenty final")
    require(len({row["source_path"] for row in manifest}) == 22, "Manifest contains duplicate source paths")
    for source in manifest:
        project_file(source["source_path"])
    require(Counter(row["split"] for row in manifest) == {"pilot": 2, "final": 20}, "Invalid manifest splits")
    final = {row["pair_id"]: row for row in manifest if row["split"] == "final"}
    require(Counter(row["cwe"] for row in final.values()) == {"CWE-121": 10, "CWE-122": 10},
            "Final split requires ten pairs per CWE")
    require(Counter(row.get("cohort") for row in final.values()) == {"original": 10, "extension": 10},
            "Final split requires original and extension cohorts")
    require(all(row.get("volatile_destination") in ("yes", "no") for row in final.values()),
            "Missing volatile-destination metadata")
    require({row["pair_id"] for row in rows} == set(final), "Truth includes missing, extra, or pilot pairs")
    cells = set(product(("vulnerable", "fixed"), ("O0", "O2"), ("retained", "stripped")))
    for pair, source in sorted(final.items()):
        group = [row for row in rows if row["pair_id"] == pair]
        require(len(group) == 8 and {(row["variant"], row["optimization"], row["symbols"]) for row in group} == cells,
                f"Unbalanced matched treatments for {pair}")
        for row in group:
            require(all(row[field] == source[field] for field in ("cwe", "source_path", "target_function")),
                    f"Truth disagrees with manifest for {pair}")
            expected = "not_vulnerable" if row["variant"] == "fixed" else f"vulnerable_{row['cwe']}"
            require(row["truth"] == expected, f"Inconsistent truth for {row['observation_id']}")
            require(row["record_path"] == f"data/records/{row['observation_id']}.json", "Nonfinal record path")
            require(extract.address(row["target_start"]) < extract.address(row["target_end"]), "Invalid target bounds")
            require(all(isinstance(row[field], str) and len(row[field]) == 64
                        and all(char in "0123456789abcdef" for char in row[field])
                        for field in ("text_sha256", "analysis_sha256")), "Invalid binary digest")
        for variant, optimization in product(("vulnerable", "fixed"), ("O0", "O2")):
            partners = [row for row in group if row["variant"] == variant and row["optimization"] == optimization]
            require(all(len({row[field] for row in partners}) == 1 for field in
                        ("target_start", "target_end", "text_sha256", "oracle_binary")), "Analysis partners disagree")
    # Private analysis strata never enter exported records or model requests.
    return sorted([{**row, **{field: final[row["pair_id"]][field]
                              for field in ("cohort", "volatile_destination")}} for row in rows],
                  key=lambda row: row["observation_id"])


def verify_input_freeze(truth):
    # Validate the existing freeze; never create one after seeing predictions.
    freeze = input_freeze.check_freeze(PROJECT_ROOT)
    require({row["record_path"] for row in truth} == input_freeze.FINAL_RECORDS,
            "Truth does not select exactly the frozen final records")
    return freeze


def load_records(truth):
    expected = {row["record_path"] for row in truth}
    actual = {path.relative_to(PROJECT_ROOT).as_posix() for path in (PROJECT_ROOT / "data/records").glob("*.json")}
    require(actual == expected, "Missing or extra final records")
    records = {}
    for row in truth:
        record = read_json(project_file(row["record_path"]))
        extract.validate_record(record)
        extract.check_expected_bounds(record, row)
        extract.scan_record_for_leaks(record, row)
        records[row["observation_id"]] = record
    return records


def load_static_predictions(records):
    path = project_file("results/static_predictions.jsonl")
    predictions = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        require(line.strip(), f"Blank static prediction at line {number}")
        prediction = run_llm.strict_json(line)
        static_baseline.validate_prediction(prediction)
        identifier = prediction["observation_id"]
        require(identifier in records and identifier not in predictions, "Extra or duplicate static prediction")
        require(set(prediction["evidence"]) <= {item["address"] for item in records[identifier]["instructions"]},
                f"Static evidence outside record: {identifier}")
        predictions[identifier] = prediction
    require(set(predictions) == set(records), "Missing static predictions")
    regenerated = {identifier: {"observation_id": identifier, **static_baseline.analyze_record(record)}
                   for identifier, record in records.items()}
    require(predictions == regenerated, "Static predictions differ from the frozen implementation")
    return predictions


def load_llm_runs(records, config):
    directory = PROJECT_ROOT / "results/llm_runs"
    schema = read_json(project_file("llm/response.schema.json"))
    prompt = project_file("llm/prompt.md").read_text(encoding="utf-8")
    require(prompt.count("{{RECORD_JSON}}") == 1, "Invalid frozen prompt")
    campaign = read_json(directory / "campaign.json")
    schedule = run_llm.make_schedule(list(records.items()), 3, config["llm"]["schedule_seed"])
    expected_campaign = {
        "schema_version": 1, "inference_config": config["llm"],
        "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
        "schema_sha256": hashlib.sha256(run_llm.canonical_json(schema).encode()).hexdigest(),
        "schedule": [{"observation_id": identifier, "repetition": repetition,
                      "request_sha256": hashlib.sha256(run_llm.canonical_json(run_llm.make_payload(
                          records[identifier], prompt, schema, config["llm"], repetition)).encode()).hexdigest()}
                     for identifier, repetition in schedule],
    }
    require(campaign == expected_campaign, "LLM campaign is not bound to the frozen records/settings")
    expected_files = {directory / identifier / f"rep{repetition}.json" for identifier, repetition in schedule}
    actual_files = {path for path in directory.rglob("*") if path.is_file()
                    and path not in {directory / "campaign.json", directory / ".runner.lock"}}
    require(actual_files == expected_files, "Missing or extra LLM run files (incomplete runs cannot be dropped)")
    hashes = {(task["observation_id"], task["repetition"]): task["request_sha256"] for task in campaign["schedule"]}
    runs = {identifier: [] for identifier in records}
    for identifier, repetition in sorted(schedule):
        run = read_json(project_file(f"results/llm_runs/{identifier}/rep{repetition}.json"))
        run_llm.validate_saved_run(run, identifier, repetition, records[identifier], schema)
        require(run["request_sha256"] == hashes[identifier, repetition]
                and run["seed"] == config["llm"]["seeds"][repetition - 1], "LLM request or seed mismatch")
        runs[identifier].append(run)
    return runs


def validate_completeness(truth, static, llm):
    ids = {row["observation_id"] for row in truth}
    require(len(truth) == 160 and len(ids) == 160 and set(static) == set(llm) == ids,
            "Evaluation requires all 160 observations from both methods")
    require(sum(len(runs) for runs in llm.values()) == 480
            and all(len(runs) == 3 and {run["repetition"] for run in runs} == {1, 2, 3} for runs in llm.values()),
            "Each observation requires exactly three saved runs, including failures")


def aggregate_three_runs(runs):
    require(len(runs) == 3, "Aggregation requires three saved runs")
    valid = [run for run in runs if run["status"] == "valid"]
    votes = Counter(run["parsed"]["decision"] for run in valid)
    majorities = [decision for decision, count in votes.items() if count >= 2]
    decision = majorities[0] if majorities else AGREEMENT_UNCERTAIN if valid else UNAVAILABLE
    return {"decision": decision,
            "confidence": statistics.median(run["parsed"]["confidence"] for run in valid) if valid else None,
            "valid_runs": len(valid), "unavailable_runs": 3 - len(valid),
            "unavailable_status_counts": dict(sorted(Counter(run["status"] for run in runs if run["status"] != "valid").items())),
            "decision_counts": dict(sorted(votes.items()))}


def score_three_way(truth, decision):
    require(truth in VULNERABLE | {"not_vulnerable"}
            and decision in static_baseline.DECISIONS | {AGREEMENT_UNCERTAIN, UNAVAILABLE}, "Invalid scoring label")
    if decision == UNAVAILABLE:
        return "unavailable"
    if decision in ABSTENTIONS:
        return "abstain"
    return "correct" if truth == decision else "incorrect"


def score_forced_alert(truth, decision):
    score_three_way(truth, decision)
    return ("tp" if decision in VULNERABLE else "fn") if truth in VULNERABLE else (
        "fp" if decision in VULNERABLE else "tn")


def cluster_counts(truth, predictions, pairs):
    result = np.zeros((len(pairs), len(COUNTS)), dtype=np.int64)
    indices = {pair: index for index, pair in enumerate(pairs)}
    for row in truth:
        decision = predictions[row["observation_id"]]["decision"]
        outcome, forced = score_three_way(row["truth"], decision), score_forced_alert(row["truth"], decision)
        counts = {"n": 1, outcome: 1, forced: 1}
        if forced in {"tn", "fn"} and outcome in {"abstain", "unavailable"}:
            counts[f"{forced}_from_{outcome}"] = 1
        if row["truth"] in VULNERABLE and decision in VULNERABLE and row["truth"] != decision:
            counts["wrong_cwe_alerts"] = 1
        result[indices[row["pair_id"]]] += [counts.get(name, 0) for name in COUNTS]
    return result


def ratio(numerator, denominator):
    numerator, denominator = np.asarray(numerator, dtype=float), np.asarray(denominator, dtype=float)
    return np.divide(numerator, denominator, out=np.full(np.broadcast_shapes(numerator.shape, denominator.shape), np.nan),
                     where=denominator > 0)


def compute_metrics(counts):
    values = {name: counts[..., index] for index, name in enumerate(COUNTS)}
    n, correct, incorrect = values["n"], values["correct"], values["incorrect"]
    tp, tn, fp, fn = (values[name] for name in ("tp", "tn", "fp", "fn"))
    values.update(correct_rate=ratio(correct, n), coverage=ratio(correct + incorrect, n),
                  abstention_rate=ratio(values["abstain"], n), unavailability_rate=ratio(values["unavailable"], n),
                  selective_accuracy=ratio(correct, correct + incorrect), accuracy=ratio(tp + tn, n),
                  balanced_accuracy=(ratio(tp, tp + fn) + ratio(tn, tn + fp)) / 2,
                  precision=ratio(tp, tp + fp), recall=ratio(tp, tp + fn),
                  f1=ratio(2 * tp, 2 * tp + fp + fn), fpr=ratio(fp, fp + tn), fnr=ratio(fn, tp + fn))
    return values


def bootstrap_weights(pairs, repetitions, seed):
    rng = np.random.Generator(np.random.PCG64(seed))
    sampled = rng.integers(0, len(pairs), size=(repetitions, len(pairs)))
    weights = np.zeros((repetitions, len(pairs)), dtype=np.int64)
    np.add.at(weights, (np.arange(repetitions)[:, None], sampled), 1)
    return weights


def cluster_bootstrap(counts, weights):
    require(weights.shape[1] == counts.shape[0], "Cluster weights do not match the paired corpus")
    return compute_metrics(weights @ counts)


def interval(samples):
    finite = np.asarray(samples)[np.isfinite(samples)]
    if not len(finite):
        return math.nan, math.nan, 0
    low, high = np.percentile(finite, [2.5, 97.5], method="linear")
    return float(low), float(high), len(finite)


def context(truth, predictions, pairs, weights):
    counts = cluster_counts(truth, predictions, pairs)
    return {"point": compute_metrics(counts.sum(axis=0)), "bootstrap": cluster_bootstrap(counts, weights),
            "pair_ids": sorted({row["pair_id"] for row in truth}),
            "n_pairs": len({row["pair_id"] for row in truth})}


def metric_rows(method, group, level, result, repetitions):
    point = result["point"]
    rows = []
    for metric in (*COUNTS, *RATES):
        low, high, defined = interval(result["bootstrap"][metric])
        rows.append({"kind": "method", "method": method, "group": group, "level": level,
                     "metric": metric, "estimate": point[metric], "ci_low": low, "ci_high": high,
                     "bootstrap_defined": defined, "bootstrap_total": repetitions, "n_pairs": result["n_pairs"],
                     **{name: point[name] for name in ("n", "correct", "incorrect", "abstain", "unavailable",
                                                       "coverage", "selective_accuracy")}})
    return rows


def paired_difference(left, right, method, group, level, left_name, right_name, repetitions):
    rows = []
    require(left["pair_ids"] == right["pair_ids"], "Contrasts require identical paired clusters")
    for metric in RATES:
        samples = left["bootstrap"][metric] - right["bootstrap"][metric]
        low, high, defined = interval(samples)
        rows.append({"kind": "paired_difference" if group == "overall" else "matched_contrast",
                     "method": method, "group": group, "level": level, "left": left_name, "right": right_name,
                     "metric": metric, "estimate": left["point"][metric] - right["point"][metric],
                     "ci_low": low, "ci_high": high, "bootstrap_defined": defined, "bootstrap_total": repetitions,
                     "n": left["point"]["n"], "n_pairs": left["n_pairs"]})
    return rows


def build_subgroups(truth, methods, pairs, weights):
    rows, contexts = [], {}
    for dimension, levels in DIMENSIONS.items():
        for level in levels:
            group = [row for row in truth if row[dimension] == level]
            for method in METHODS:
                result = context(group, methods[method], pairs, weights)
                contexts[method, dimension, level] = result
                rows.extend(metric_rows(method, dimension, level, result, len(weights)))
    for method in METHODS:
        for dimension in ("optimization", "symbols"):
            low, high = DIMENSIONS[dimension]
            # Full 2x2x2 truth-matrix validation makes these matched cells.
            rows.extend(paired_difference(contexts[method, dimension, high], contexts[method, dimension, low],
                                          method, dimension, f"{high}_minus_{low}", high, low, len(weights)))
    return rows, contexts


def summarize_stability(truth, runs, aggregates, threshold):
    observations = []
    agree, comparisons = 0, 0
    for row in truth:
        identifier = row["observation_id"]
        aggregate = aggregates[identifier]
        valid = [run["parsed"]["decision"] for run in runs[identifier] if run["status"] == "valid"]
        local_pairs = list(combinations(valid, 2))
        local_agree = sum(left == right for left, right in local_pairs)
        outcome = score_three_way(row["truth"], aggregate["decision"])
        agree += local_agree
        comparisons += len(local_pairs)
        observations.append({"kind": "observation", "observation_id": identifier, **aggregate,
                             "outcome": outcome, "three_valid": int(len(valid) == 3),
                             "three_identical": int(len(valid) == 3 and len(set(valid)) == 1),
                             "agreement_pairs": local_agree, "valid_pairs": len(local_pairs),
                             "high_confidence_error": int(outcome == "incorrect" and aggregate["confidence"] >= threshold)})
    stats = {
        "observations": len(truth), "runs": sum(len(group) for group in runs.values()),
        "three_valid_observations": sum(row["three_valid"] for row in observations),
        "three_identical_observations": sum(row["three_identical"] for row in observations),
        "agreement_pairs": agree, "valid_pairs": comparisons,
        "pairwise_agreement": agree / comparisons if comparisons else math.nan,
        "model_uncertain_votes": sum(run["status"] == "valid" and run["parsed"]["decision"] == "uncertain"
                                     for group in runs.values() for run in group),
        "model_uncertain_aggregates": sum(row["decision"] == "uncertain" for row in observations),
        "insufficient_agreement_aggregates": sum(row["decision"] == AGREEMENT_UNCERTAIN for row in observations),
        "unavailable_aggregates": sum(row["decision"] == UNAVAILABLE for row in observations),
        "high_confidence_threshold": threshold,
        "high_confidence_errors": sum(row["high_confidence_error"] for row in observations),
    }
    for status in sorted(run_llm.FAILURES):
        stats[f"invalid_runs_{status}"] = sum(run["status"] == status for group in runs.values() for run in group)
    for outcome in ("correct", "incorrect", "abstain"):
        values = [row["confidence"] for row in observations if row["outcome"] == outcome and row["confidence"] is not None]
        stats[f"median_confidence_{outcome}"] = statistics.median(values) if values else math.nan
    rows = [{"kind": "summary", "metric": metric, "estimate": value} for metric, value in sorted(stats.items())]
    rows.extend(observations)
    return rows, stats


def csv_value(value):
    if isinstance(value, np.ndarray):
        require(value.ndim == 0, "Cannot serialize a nonscalar metric into one CSV cell")
        value = value.item()
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return run_llm.canonical_json(value)
    if isinstance(value, (float, np.floating)):
        return f"{float(value):.9f}".rstrip("0").rstrip(".") if math.isfinite(value) else ""
    if isinstance(value, np.integer):
        return str(int(value))
    return value


def write_csv(path, rows, fields):
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            require(set(row) <= set(fields), "Unexpected generated table column")
            writer.writerow({key: csv_value(value) for key, value in row.items()})


def make_figures(destination, overall, groups):
    # An isolated Matplotlib configuration prevents user styles/cache paths
    # from affecting PNG bytes or writing outside the regeneration workspace.
    with tempfile.TemporaryDirectory(prefix="evaluate-mpl-") as cache:
        previous = os.environ.get("MPLCONFIGDIR")
        os.environ["MPLCONFIGDIR"] = cache
        try:
            import matplotlib as mpl
            from matplotlib.backends.backend_agg import FigureCanvasAgg
            from matplotlib.figure import Figure
            import PIL
            with mpl.rc_context(rc=mpl.rcParamsDefault):
                mpl.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9})
                colors = {"static": "#1f77b4", "llm_majority": "#d95f02"}
                names = {"static": "Static", "llm_majority": "LLM majority"}

                def dot(axis, x, result, metric, color, label=None):
                    point = float(result["point"][metric])
                    low, high, _ = interval(result["bootstrap"][metric])
                    if math.isfinite(low):
                        axis.vlines(x, low, high, color=color, linewidth=1.5)
                        axis.hlines([low, high], x - .035, x + .035, color=color)
                    if math.isfinite(point):
                        axis.plot(x, point, "o", color=color, label=label)
                    return point

                def label_height(result, metric):
                    value = float(result["point"][metric])
                    _, high, _ = interval(result["bootstrap"][metric])
                    if not math.isfinite(value):
                        return .5
                    return min(max(value, high if math.isfinite(high) else value) + .04, 1.07)

                def base(titles):
                    figure = Figure(figsize=(9, 5), dpi=150)
                    FigureCanvasAgg(figure)
                    axes = figure.subplots(1, 2)
                    figure.subplots_adjust(left=.09, right=.98, bottom=.28, top=.88, wspace=.30)
                    for axis, title in zip(axes, titles):
                        axis.set_title(title)
                        axis.set_ylim(-.04, 1.19)
                        axis.set_yticks(np.arange(0, 1.01, .2), [f"{value:.0%}" for value in np.arange(0, 1.01, .2)])
                        axis.grid(axis="y", alpha=.25)
                    return figure, axes

                def save(figure, name):
                    figure.savefig(destination / "figures" / name, format="png", dpi=150,
                                   metadata={"Software": "optimization-vuln-analysis"})
                    figure.clear()

                figure, axes = base(("Coverage", "Selective accuracy"))
                for axis, metric in zip(axes, ("coverage", "selective_accuracy")):
                    axis.set_xticks(range(2), [names[method] for method in METHODS])
                    axis.set_xlim(-.5, 1.5)
                    for x, method in enumerate(METHODS):
                        result = overall[method]
                        value = dot(axis, x, result, metric, colors[method])
                        low, high, _ = interval(result["bootstrap"][metric])
                        text = "NA" if not math.isfinite(value) else f"{value:.1%}\n[{low:.1%}, {high:.1%}]"
                        axis.text(x, label_height(result, metric), text,
                                  ha="center", va="bottom", fontsize=8)
                lines = []
                for method in METHODS:
                    p = overall[method]["point"]
                    lines.append(f"{names[method]}: N={int(p['n'])}, correct={int(p['correct'])}, incorrect={int(p['incorrect'])}, "
                                 f"abstain={int(p['abstain'])}, unavailable={int(p['unavailable'])}")
                figure.text(.5, .10, "\n".join(lines) + "\nBars: exploratory 95% pair-cluster intervals.", ha="center", va="center", fontsize=8)
                save(figure, "coverage_accuracy.png")

                figure, axes = base(("Forced-alert recall", "Forced-alert false-positive rate"))
                for axis, metric in zip(axes, ("recall", "fpr")):
                    axis.set_xticks(range(2), [names[method] for method in METHODS])
                    axis.set_xlim(-.5, 1.5)
                    for x, method in enumerate(METHODS):
                        result = overall[method]
                        value = dot(axis, x, result, metric, colors[method])
                        p = result["point"]
                        numerator = p["tp"] if metric == "recall" else p["fp"]
                        denominator = p["tp"] + p["fn"] if metric == "recall" else p["fp"] + p["tn"]
                        text = f"{value:.1%}\n{int(numerator)}/{int(denominator)}" if math.isfinite(value) else "NA"
                        axis.text(x, label_height(result, metric), text, ha="center", fontsize=8)
                figure.text(.5, .10, "Either vulnerable label is an alert; abstention and unavailability are no alert.\n"
                            "Bars: exploratory 95% pair-cluster intervals.", ha="center", va="center", fontsize=8)
                save(figure, "recall_fpr.png")

                figure, axes = base(("Optimization: forced accuracy", "Symbols: forced accuracy"))
                for axis, dimension in zip(axes, ("optimization", "symbols")):
                    levels = DIMENSIONS[dimension]
                    axis.set_xticks(range(2), levels)
                    axis.set_xlim(-.5, 1.5)
                    for index, method in enumerate(METHODS):
                        for x, level in enumerate(levels):
                            result = groups[method, dimension, level]
                            position = x + (-.14 if index == 0 else .14)
                            value = dot(axis, position, result, "accuracy", colors[method], names[method] if x == 0 else None)
                            p = result["point"]
                            axis.text(position, label_height(result, "accuracy"), f"{value:.0%}\n{int(p['tp']+p['tn'])}/{int(p['n'])}",
                                      ha="center", fontsize=7, color=colors[method])
                handles, labels = axes[0].get_legend_handles_labels()
                figure.legend(handles, labels, loc="lower center", bbox_to_anchor=(.5, .15), ncol=2, frameon=False, fontsize=8)
                figure.text(.5, .07, "Balanced matched conditions; optimization and symbols are separate comparisons.\n"
                            "Bars: exploratory 95% pair-cluster intervals.", ha="center", va="center", fontsize=8)
                save(figure, "treatment_accuracy.png")
            return {"python": platform.python_version(), "numpy": np.__version__,
                    "matplotlib": mpl.__version__, "pillow": PIL.__version__}
        finally:
            if previous is None:
                os.environ.pop("MPLCONFIGDIR", None)
            else:
                os.environ["MPLCONFIGDIR"] = previous


def formatted(result, metric, percentage=True):
    value = float(result["point"][metric])
    low, high, _ = interval(result["bootstrap"][metric])
    if not math.isfinite(value):
        return "NA"
    fmt = (lambda number: f"{100 * number:.1f}%") if percentage else (lambda number: f"{number:.3f}")
    return f"{fmt(value)} [{fmt(low)}, {fmt(high)}]" if math.isfinite(low) else f"{fmt(value)} [NA]"


def write_report(destination, truth, overall, groups, summary, subgroups, stability, all_rows, config,
                 diagnostics=None):
    names = {"static": "Static", "llm_majority": "LLM majority"}
    pair_count = len({row["pair_id"] for row in truth})
    lines = ["# Final analysis", "", f"{len(truth)} observations from {pair_count} source pairs; pilot pairs are excluded.", "",
             "This is a reviewed, exploratory convenience corpus, not an untouched held-out validation. "
             "Function localization is supplied by the oracle. Function attributes and volatile destinations "
             "constrain optimization; conclusions are conditional on these controlled fixtures.", "",
             "Intervals are exploratory 95% pair-cluster percentile intervals. With only "
             f"{pair_count} clusters they may be unstable; they are not confirmatory significance tests.", "",
             "## Three-way performance", "",
             "| Method | N | Correct | Incorrect | Abstain | Unavailable | Correct/N (95% interval) | Coverage (95% interval) | Selective accuracy (95% interval) |",
             "|---|---:|---:|---:|---:|---:|---|---|---|"]
    for method in METHODS:
        p = overall[method]["point"]
        lines.append(f"| {names[method]} | " + " | ".join(str(int(p[name])) for name in
                     ("n", "correct", "incorrect", "abstain", "unavailable")) + " | " + " | ".join(
                         formatted(overall[method], metric) for metric in ("correct_rate", "coverage", "selective_accuracy")) + " |")
    lines += ["", "Abstention rates (95% intervals): " + "; ".join(
                  f"{names[method]} {formatted(overall[method], 'abstention_rate')}" for method in METHODS) + ".",
              "", "Unavailability rates (95% intervals): " + "; ".join(
                  f"{names[method]} {formatted(overall[method], 'unavailability_rate')}" for method in METHODS) + ".",
              "", "CWE labels are indivisible: a wrong-CWE alert is three-way incorrect. Both uncertainty types abstain; unavailable is separate.",
              "", "## Forced binary alerts", "",
              "| Method | TP | TN | FP | FN | TN from abstain | TN from unavailable | FN from abstain | FN from unavailable | Wrong-CWE alerts |",
              "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for method in METHODS:
        p = overall[method]["point"]
        lines.append(f"| {names[method]} | " + " | ".join(str(int(p[name])) for name in
                     ("tp", "tn", "fp", "fn", "tn_from_abstain", "tn_from_unavailable",
                      "fn_from_abstain", "fn_from_unavailable", "wrong_cwe_alerts")) + " |")
    lines += ["", "Either vulnerable label is an alert. Explicit safe decisions, abstentions, and unavailable results all become no alert; their TN/FN contributions above remain distinct.",
              "", "| Forced metric | Static (95% interval) | LLM majority (95% interval) |", "|---|---|---|"]
    for metric in ("accuracy", "balanced_accuracy", "precision", "recall", "f1", "fpr", "fnr"):
        lines.append(f"| {metric} | {formatted(overall['static'], metric)} | {formatted(overall['llm_majority'], metric)} |")
    lines += ["", "## Paired method differences", "", "LLM majority minus static, in percentage points; shared sampled weights are used on both sides.",
              "", "| Primary metric | Difference [95% interval], pp | Defined replicates |", "|---|---:|---:|"]
    for row in summary:
        if row["kind"] == "paired_difference" and row["metric"] in {"correct_rate", "coverage", "recall", "fpr"}:
            value = "NA" if not math.isfinite(row["estimate"]) else f"{100*row['estimate']:.1f} [{100*row['ci_low']:.1f}, {100*row['ci_high']:.1f}]"
            lines.append(f"| {row['metric']} | {value} | {row['bootstrap_defined']}/{row['bootstrap_total']} |")
    lines += ["", "## Matched treatment contrasts", "", "Every comparison retains the same pairs and matched variant/other-treatment cells. Values are forced accuracy."]
    for dimension in ("optimization", "symbols"):
        low, high = DIMENSIONS[dimension]
        lines += ["", f"| Method | {low} (95% interval) | {high} (95% interval) | {high} minus {low}, pp [95% interval] |", "|---|---|---|---|"]
        for method in METHODS:
            contrast = next(row for row in subgroups if row["kind"] == "matched_contrast" and row["method"] == method
                            and row["group"] == dimension and row["metric"] == "accuracy")
            lines.append(f"| {names[method]} | {formatted(groups[method, dimension, low], 'accuracy')} | "
                         f"{formatted(groups[method, dimension, high], 'accuracy')} | "
                         f"{100*contrast['estimate']:.1f} [{100*contrast['ci_low']:.1f}, {100*contrast['ci_high']:.1f}] |")
    lines += ["", "## Corpus strata", "",
              "Cohort and volatile strata are descriptive comparisons, not randomized treatments or evidence of independent generalization.", "",
              "| Stratum | Level | Method | N | Correct/N (95% interval) | Coverage (95% interval) |",
              "|---|---|---|---:|---|---|"]
    for dimension in ("cohort", "volatile_destination"):
        for level in DIMENSIONS[dimension]:
            for method in METHODS:
                result = groups[method, dimension, level]
                lines.append(f"| {dimension} | {level} | {names[method]} | {int(result['point']['n'])} | "
                             f"{formatted(result, 'correct_rate')} | {formatted(result, 'coverage')} |")
    if diagnostics is not None:
        audit = diagnostics['collision_audit']['full_record']
        matches = diagnostics['stripping_matches']
        equal = sum(row['equal_after_name_normalization'] for row in matches)
        lines += ["", "## Evidence observability", "",
                  f"{len(audit['conflicting_ids'])} observations have conflicting source labels on identical inputs. "
                  "These cases cannot be distinguished consistently from the supplied evidence; full scores are retained. "
                  "The input-equality sensitivity excludes every member of each conflicting group, independent of predictions.", "",
                  "| Method | Distinguishable correct/N | Coverage |", "|---|---:|---:|"]
        for method, values in diagnostics['distinguishable_sensitivity']['methods'].items():
            coverage = values['coverage']
            lines.append(f"| {method} | {values['correct']}/{values['n']} | "
                         + (f"{coverage:.1%}" if coverage is not None else "NA") + " |")
        lines += ["", f"{equal}/{len(matches)} retained/stripped matches are identical after neutralizing function names."]
        if matches and equal == len(matches):
            lines += ["The symbol condition measures neutral-name sensitivity plus sampling variation. "
                      "It does not test loss of meaningful developer symbols."]
    invalid = {key.removeprefix("invalid_runs_"): value for key, value in stability.items() if key.startswith("invalid_runs_")}
    medians = ", ".join(f"{outcome}={csv_value(stability[f'median_confidence_{outcome}']) or 'NA'}"
                        for outcome in ("correct", "incorrect", "abstain"))
    agreement = f"{stability['pairwise_agreement']:.1%}" if math.isfinite(stability['pairwise_agreement']) else "NA"
    lines += ["", "## LLM stability and confidence", "",
              f"Three valid runs: {stability['three_valid_observations']}/{len(truth)} observations. "
              f"All three decisions identical (all valid): {stability['three_identical_observations']}/{len(truth)}.", "",
              f"Pooled pairwise agreement among valid runs: {stability['agreement_pairs']}/{stability['valid_pairs']} "
              f"({agreement}). Failed runs are excluded from this denominator, not replaced by uncertainty.", "",
              "Invalid run counts: " + ", ".join(f"{key}={value}" for key, value in sorted(invalid.items())) + ".", "",
              f"Model-produced uncertain votes: {stability['model_uncertain_votes']}; majority-uncertain observations: "
              f"{stability['model_uncertain_aggregates']}; insufficient-agreement observations: "
              f"{stability['insufficient_agreement_aggregates']}; all-unavailable observations: {stability['unavailable_aggregates']}.", "",
              f"Median self-reported run confidence by three-way outcome: {medians}. Each observation pools all valid runs, including different voted labels; this is not a probability that its majority label is correct.", "",
              f"High-confidence three-way errors at confidence >= {stability['high_confidence_threshold']:g}: {stability['high_confidence_errors']}.", "",
              "## Interpretation and regeneration", "",
              "Undefined denominators are NA (blank CSV cells), never zero. Intervals use only jointly defined replicates; "
              "every metric row reports bootstrap_defined/bootstrap_total. Sparse subgroup intervals are conditional on defined replicates.", "",
              f"Bootstrap: {config['evaluation']['bootstrap_repetitions']} draws of {pair_count} pairs with replacement; "
              f"PCG64 seed {config['evaluation']['bootstrap_seed']}; linear 2.5th/97.5th percentiles. "
              "All methods, subgroups, and matched contrasts share the same draws.", "",
              "Full counts, rates, and intervals are in summary.csv and subgroups.csv; per-observation votes, failures, and confidence are in stability.csv. "
              "These results concern selected target operations in this small corpus, compiler, extractor, and local model. They do not establish production-scanner performance.", "",
              "This compares complete pipelines: the LLM receives decompilation plus assembly, while the restricted static interpreter consumes assembly/calls. Differences cannot be attributed to LLM reasoning alone. The original and extension cohorts have been inspected during development; neither is an untouched test set. Source revisions and these additional analyses are exploratory.", "",
              "Forced accuracy includes safe-program abstentions as true negatives; lead interpretation with correct/N and coverage. The twenty source pairs are the sampling units; related templates and exact input collisions limit diversity. Bootstrap intervals reflect this small corpus; a degenerate zero-error interval does not establish population precision or interpreter soundness.", "",
              "See [exploratory diagnostics](exploratory.md) for input collisions, distinguishable-input sensitivity, paired repair discrimination, stripping transitions, per-pair sensitivity, and compute accounting. Oracle reviews recorded as Codex do not constitute independent human adjudication. A hash inventory alone does not independently establish freeze chronology.", "",
              "![Coverage and selective accuracy](figures/coverage_accuracy.png)", "",
              "![Forced recall and false-positive rate](figures/recall_fpr.png)", "",
              "![Matched treatment accuracy](figures/treatment_accuracy.png)", ""]
    undefined = sum(row["bootstrap_defined"] < row["bootstrap_total"] for row in all_rows)
    lines.insert(lines.index("## Interpretation and regeneration") + 2,
                 f"{undefined} metric rows have fewer than all bootstrap replicates defined.\n")
    (destination / "report.md").write_text("\n".join(lines), encoding="utf-8")


def capture_inputs(freeze, truth):
    inputs = set(freeze["files"]) | {"data/input_freeze.json", "data/private/observations.csv",
             "results/static_predictions.jsonl", "results/llm_runs/campaign.json", "pipeline/evaluate.py", "pipeline/extract.py"}
    inputs.update(f"results/llm_runs/{row['observation_id']}/rep{repetition}.json" for row in truth for repetition in range(1, 4))
    # Include the actual inventories as well, to detect additions during analysis.
    inputs.update(path.relative_to(PROJECT_ROOT).as_posix() for path in (PROJECT_ROOT / "data/records").glob("*.json"))
    inputs.update(path.relative_to(PROJECT_ROOT).as_posix() for path in (PROJECT_ROOT / "results/llm_runs").rglob("*")
                  if path.is_file() and path != PROJECT_ROOT / "results/llm_runs/.runner.lock")
    if (PROJECT_ROOT / "results/qualitative.md").exists():
        inputs.add("results/qualitative.md")
    return {name: digest(project_file(name)) for name in sorted(inputs)}


def write_release_manifest(destination, truth, environment, config, input_hashes):
    files = dict(input_hashes)
    files.update({f"results/{name}": digest(destination / name) for name in sorted(ARTIFACTS - {"release_manifest.json"})})
    manifest = {"release_version": 1, "observations": len(truth), "pairs": len({row['pair_id'] for row in truth}),
                "llm_runs": 3 * len(truth), "evaluation": config["evaluation"], "environment": environment,
                "files": dict(sorted(files.items()))}
    run_llm.write_run_atomically(destination / "release_manifest.json", manifest)


def artifact_inventory(directory):
    if not directory.exists():
        return set()
    files = set()
    for path in directory.iterdir():
        if path.name in {"llm_runs", "pilot", "static_predictions.jsonl", "qualitative.md"}:
            continue  # Inputs and development results are outside output scope.
        if path.is_file() or path.is_symlink():
            files.add(path.relative_to(directory).as_posix())
        elif path.is_dir():
            files.update(child.relative_to(directory).as_posix() for child in path.rglob("*")
                         if child.is_file() or child.is_symlink())
    return files


def check_regeneration(generated, published):
    expected, actual = artifact_inventory(generated), artifact_inventory(published)
    require(expected == ARTIFACTS, "Internal error: generated artifact set is incomplete or unexpected")
    missing, extra = expected - actual, actual - expected
    changed = {name for name in expected & actual
               if (published / name).is_symlink() or digest(generated / name) != digest(published / name)}
    require(not (missing or extra or changed),
            f"Regeneration mismatch: missing={sorted(missing)}, extra={sorted(extra)}, changed={sorted(changed)}")


def generate(destination, truth, static, llm, freeze, config, input_hashes=None):
    input_hashes = capture_inputs(freeze, truth) if input_hashes is None else input_hashes
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "figures").mkdir()
    pairs = sorted({row["pair_id"] for row in truth})
    aggregates = {identifier: aggregate_three_runs(runs) for identifier, runs in sorted(llm.items())}
    methods = {"static": static, "llm_majority": aggregates}
    weights = bootstrap_weights(pairs, config["evaluation"]["bootstrap_repetitions"], config["evaluation"]["bootstrap_seed"])
    overall = {method: context(truth, methods[method], pairs, weights) for method in METHODS}
    summary = [row for method in METHODS for row in metric_rows(method, "overall", "all", overall[method], len(weights))]
    summary.extend(paired_difference(overall["llm_majority"], overall["static"], "llm_majority_minus_static",
                                     "overall", "all", "llm_majority", "static", len(weights)))
    subgroups, group_contexts = build_subgroups(truth, methods, pairs, weights)
    stability_rows, stability = summarize_stability(truth, llm, aggregates, config["evaluation"]["confidence_threshold"])
    write_csv(destination / "summary.csv", summary, TABLE_FIELDS)
    write_csv(destination / "subgroups.csv", subgroups, TABLE_FIELDS)
    stability_fields = ("kind", "metric", "estimate", "observation_id", "decision", "confidence", "outcome", "valid_runs",
                        "unavailable_runs", "unavailable_status_counts", "decision_counts", "three_valid", "three_identical",
                        "agreement_pairs", "valid_pairs", "high_confidence_error")
    write_csv(destination / "stability.csv", stability_rows, stability_fields)
    environment = make_figures(destination, overall, group_contexts)
    if __package__:
        from . import diagnostics
    else:
        import diagnostics
    audit = diagnostics.write(destination, truth, load_records(truth), methods, llm)
    write_report(destination, truth, overall, group_contexts, summary, subgroups, stability,
                 summary + subgroups, config, audit)
    write_release_manifest(destination, truth, environment, config, input_hashes)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Regenerate in a temporary directory and compare every output SHA-256")
    args = parser.parse_args(argv)
    require((PROJECT_ROOT / "analysis_plan.md").is_file()
            and (PROJECT_ROOT / "analysis_plan.md").read_text(encoding="utf-8").strip(),
            "Missing or empty analysis_plan.md; freeze the plan before final inference")
    plan_hash = digest(PROJECT_ROOT / "analysis_plan.md")
    config_hash = digest(PROJECT_ROOT / "config.json")
    config = load_config()
    truth_path = PROJECT_ROOT / "data/private/observations.csv"
    require(truth_path.is_file() and truth_path.stat().st_size, "Missing or empty final truth table: data/private/observations.csv")
    truth_hash = digest(truth_path)
    truth = load_truth()
    freeze = verify_input_freeze(truth)
    input_hashes = capture_inputs(freeze, truth)
    require(input_hashes["analysis_plan.md"] == plan_hash and input_hashes["config.json"] == config_hash
            and input_hashes["data/private/observations.csv"] == truth_hash, "Inputs changed while loading evaluation metadata")
    records = load_records(truth)
    static, llm = load_static_predictions(records), load_llm_runs(records, config)
    validate_completeness(truth, static, llm)
    published = PROJECT_ROOT / "results"
    if not args.check:
        require(not (artifact_inventory(published) - ARTIFACTS), "Unexpected output artifacts; inspect results before regenerating")
    with tempfile.TemporaryDirectory(prefix="evaluate-") as directory:
        generated = Path(directory)
        generate(generated, truth, static, llm, freeze, config, input_hashes)
        # Recheck all frozen files before publishing after potentially long work.
        require(verify_input_freeze(truth) == freeze, "Input freeze changed during evaluation")
        require(capture_inputs(freeze, truth) == input_hashes, "Evaluation inputs changed during regeneration; no outputs published")
        if args.check:
            check_regeneration(generated, published)
            print(f"Verified all {len(ARTIFACTS)} output artifacts byte for byte; no published outputs changed")
        else:
            for name in sorted(ARTIFACTS - {"release_manifest.json"}) + ["release_manifest.json"]:
                target = published / name
                target.parent.mkdir(parents=True, exist_ok=True)
                temporary = None
                try:
                    with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as stream:
                        temporary = Path(stream.name)
                        with (generated / name).open("rb") as source:
                            shutil.copyfileobj(source, stream)
                        stream.flush()
                        os.fsync(stream.fileno())
                    temporary.replace(target)
                finally:
                    if temporary is not None:
                        temporary.unlink(missing_ok=True)
            print("Wrote final tables, report, three figures, and release manifest for 160 observations")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, TypeError) as error:
        print(f"Evaluation failed: {error}", file=sys.stderr)
        sys.exit(1)
