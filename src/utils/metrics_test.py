from utils import compute_results, compute_precision_recall_accuracy, compute_prec_recall_multiclass, group_metrics
import pandas as pd
import sys
import os
import tabulate
import argparse


def gen_table(output_folder, group_by_col=None, dataset_csv_path=None, dataset_index_col=None, top_cwe=False, indices=None, max_samples=None, do_cwe=False):
    results = compute_results(output_folder)
    table = []
    df = pd.DataFrame.from_dict(results, orient="index")
    if top_cwe:
        top25=open('utils/cwe_top_25.txt').read().strip().split('\n')
        print("Filtering by top 25 cwes..")
        
        df=df[df['true_cwe'].isin(top25)]
    if indices:
        print("Filtering by indices")
        indices = open(indices).read().strip().split('\n')
        df = df[df.index.isin(indices)]
    if max_samples:
        df=df.iloc[:max_samples]

    if group_by_col:
        if not dataset_csv_path:
            raise Exception("Dataset CSV Path not provided for grouped metrics computation")
        df = group_metrics(df, group_by_col, dataset_csv_path, dataset_index_col)

    all = compute_precision_recall_accuracy(df, "true_label", "llm_label")
    table.append(
        [
            "All",
            len(df),
            all["TP"],            
            all["TN"],
            all["FP"],
            all["FN"],
            all["accuracy"],
            all["accuracy_balanced"],
            all["precision"],
            all["recall"],
            all["F1"]
        ]
    )
    if do_cwe:
        cwes = list(df["true_cwe"].unique())
        for cwe in cwes:
            cwe_df = df[df["true_cwe"] == cwe]
            prec_recall = compute_precision_recall_accuracy(
                cwe_df, "true_label", "llm_label"
            )
            table.append(
                [
                    "CWE-" + str(cwe),
                    len(cwe_df),
                    int(prec_recall["TP"]),
                    int(prec_recall["TN"]),
                    int(prec_recall["FP"]),
                    int(prec_recall["FN"]),
                    prec_recall["accuracy"],
                    prec_recall["precision"],
                    prec_recall["recall"],
                    prec_recall["F1"]
                    
                ]
            )
    print(
        tabulate.tabulate(
            table,
            headers=["CWE", "Count" "TP", "TN", "FP", "FN", "Accuracy", "AccBalanced", "Precision", "Recall", "F1"],
            tablefmt="orgtbl",
        )
    )
    print(
        tabulate.tabulate(
            table,
            headers=["CWE","Count", "TP", "TN", "FP", "FN", "Accuracy", "AccBalanced", "Precision", "Recall", "F1"],
            tablefmt="latex",
            floatfmt=(".0f", ".0f", ".0f", ".0f", ".0f", ".2f",".2f", ".2f", ".2f"),
        )
    )


def get_results_from_folder(output_folder, logger=None):
    results = compute_results(output_folder)
    if logger is None:
        _log = lambda x: print(x)
    else:
        _log = _log
    df = pd.DataFrame.from_dict(results, orient="index")

    prec_recall = compute_precision_recall_accuracy(df, "true_label", "llm_label")
    # print results
    _log(">>Total samples: " + str(len(df)))
    _log(">>Total vulnerable: " + str(len(df[df["true_label"] == True])))
    _log(">>Total not vulnerable: " + str(len(df[df["true_label"] == False])))

    _log(">>Accuracy: " + str(prec_recall["accuracy"]))
    _log(">>Recall: " + str(prec_recall["recall"]))
    _log(">>Precision: " + str(prec_recall["precision"]))
    _log(">>F1: " + str(prec_recall["f1"]))

    _log(">>Total correct CWE: " + str(len(df[df["cwe_correct"] == True])))
    _log(
        ">>Total correct CWE and Label: "
        + str(len(df[(df["cwe_correct"] == True) & (df["correct"] == True)]))
    )

    # cwe specific results
    precision_dict, recall_dict, accuracy_dict = compute_prec_recall_multiclass(
        df, "true_cwe", "llm_cwe"
    )
    for k in precision_dict.keys():
        _log(
            ">>CWE: "
            + str(k)
            + ",Accuracy: "
            + str(accuracy_dict[k])
            + ",Precision: "
            + str(precision_dict[k])
            + ",Recall: "
            + str(recall_dict[k])
            
        )


if __name__ == "__main__":
    argparse = argparse.ArgumentParser()
    argparse.add_argument("--results_dir", type=str, default="Path to results directory")
    argparse.add_argument("--group_by", type=str, default=None, help="Column in the dataset to be used for grouping results (default: None)")
    argparse.add_argument("--dataset_csv_path", type=str, help="Path to dataset CSV. Required for grouped metrics")
    argparse.add_argument("--dataset_index_col", type=str, default=None, help="Column in the dataset that maps to the results indexes (used for group joins)")
    argparse.add_argument("--top_cwe", action='store_true')
    argparse.add_argument("--indices", type=str, default=None)
    argparse.add_argument("--max_samples", type=int, default=None)
    argparse.add_argument("--cwe", action='store_true')
    args = argparse.parse_args()

    gen_table(args.results_dir, args.group_by, args.dataset_csv_path, args.dataset_index_col, args.top_cwe, args.indices, args.max_samples, args.cwe)
