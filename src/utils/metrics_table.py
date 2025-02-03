import tabulate 
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
import os 
import sys 
from glob import glob 
import pandas as pd
from utils import compute_results, compute_precision_recall_accuracy
import numpy as np

model_name_map={
    'gpt-4': 'GPT-4',
    'gpt-3.5-turbo': 'GPT-3.5',
    'codellama-70b-instruct': 'CodeLlama 70b',
    'codellama-34b-instruct': '\\clamathirtyfourabv',
    'codellama-13b-instruct': '\\clamathrabv',
    'codellama-7b-instruct': '\\clamasvnabv',
    'mistral-codestral-22b': 'codestral-22b',
    'deepseekcoder-7b': 'DSCoder 7b',
    'deepseekcoder-v2-15b': 'DSCoder V2 15B',
    'deepseekcoder-33b': 'DSCoder 33b',
    'llama-3.1-8b': 'LLama 3.1 8b',
    'llama-3.1-70b': 'Llama 3.1 70b',
    'qwen2.5-14b': 'Qwen 2.5 14B',
    'qwen2.5-coder-7b' : 'Qwen 2.5 Coder 7b',
    'qwen2.5-coder-1.5b': 'Qwen 2.5 Coder 1.5b',
    'qwen2.5-32b': 'Qwen 2.5 32B'
}

prompt_type_map={
    ('simple','generic'): '\\generic',
    ('generic', 'generic'): '\\generic',
    ('simple', 'cwe_specific'): '\\cwespecific',
    ('generic', 'cwe_specific'): '\\cwespecific',
    ('dataflow_steps', 'cwe_specific'): '\\df',
    ('generic', 'cpp_few_shot'): '\\fewshot',
    ('generic', 'java_few_shot'): '\\fewshot',
    ('cot', 'zero_shot_cot_cwe'): '\\cot',
    ('cot', 'zero_shot_cot'): '\\cot'
}

dataset_map={
    'owasp': 'OWASP',
    'juliet-java-1.3': 'Juliet Java',
    'cvefixes-java-method': 'CVEFixes Java',
    'juliet-cpp-1.3': 'Juliet C/C++',
    'cvefixes-c-cpp-method': 'CVEFixes C/C++'

}

mapper={
        'prompt-basic_user-generic_system-simple': ('simple','generic'), 
        'prompt-basic_user-cwe_specific_system-simple': ('simple', 'cwe_specific')
        }

def filter_df(df, indices=None, max_samples=None):   
    top25=open('utils/cwe_top_25.txt').read().strip().split('\n')
    df=df[df['true_cwe'].isin(top25)]
    if indices is not None:
        indices = open(indices).read().strip().split('\n')       
       
        df = df[df.index.astype(str).isin(indices)]
       
    if max_samples:
        df=df.iloc[:max_samples]
    return df

def filter_by_indices(all_results_df):
    for d in all_results_df:
        df=all_results_df[d][0]
        if 'juliet-cpp-1.3' in d:
            df=filter_df(df, indices='data/juliet-cpp-1.3-1000-2048.txt')
        elif 'juliet-java-1.3' in d:
            df=filter_df(df, indices='data/juliet-java-1.3-1000-2048.txt')
        elif 'cvefixes-c-cpp' in d:
            df=filter_df(df, indices='data/cvefixes-c-cpp-method-1000-2048.txt')
            #df=filter_df(df, max_samples=2000)        
        elif 'cvefixes-java' in d:
            df=filter_df(df, indices='data/cvefixes-java-method-1000-2048.txt')
        elif 'owasp' in d:
            df=filter_df(df, indices='data/owasp-1000-2048.txt')
        all_results_df[d][0]=df


def filter_common_indices(all_results_df):
    datasets = ['owasp', 'juliet-java-1.3', 'cvefixes-java-method', 'juliet-cpp-1.3', 'cvefixes-c-cpp-method']
    indices = dict()
    for ds in datasets:
        dfs = [k for k in all_results_df if all_results_df[k][1]['Dataset'] == ds]
        indices[ds] = set(all_results_df[dfs[0]][0].index)
        for d in dfs[1:]:
            indices[ds] = indices[ds].intersection(set(all_results_df[d][0].index))
    for d in all_results_df:
        df = all_results_df[d][0]
        all_results_df[d][0] = df[df.index.isin(list(indices[all_results_df[d][1]['Dataset']]))]



def process(main_dir, lang, models, prompts, datasets, from_cache=True):
    all_results=dict()
    for d in glob(main_dir+"/*", recursive=True):
        if not os.path.isdir(d):
            continue
        if lang == "java":
            if not ('owasp' in d or 'juliet-java' in d or 'cvefixes-java' in d):
                continue
        if lang == "cpp":
            if not ('juliet-cpp' in d or 'cvefixes-c-cpp' in d):
                continue
        if not any([m in d for m in models]):
            continue
        print(d)
        if from_cache and os.path.exists(os.path.join(d, 'cache.csv')):
            df=pd.read_csv(os.path.join(d, 'cache.csv'), index_col=0, header=0, dtype={'true_cwe': str, 'llm_cwe_raw': str, 'llm_label_raw': str})
            df.index = df.index.astype(str)
            print("Loaded from cache")
            if len(df) == 0:
                continue
        else:
            results = compute_results(d, from_cache)
            df=pd.DataFrame.from_dict(results, orient="index")
            if len(df) == 0:
                continue
            df.to_csv(os.path.join(d, 'cache.csv'))
        

        missing_labels=df[df['llm_label_raw'].isnull()]
        missing_cwes=df[df['llm_cwe_raw'].isnull()]
        
        print("!!Missing labels: {}/{}".format(len(missing_labels), len(df)))
        print("!!Missing cwes: {}/{}".format(len(missing_cwes), len(df)))
        
        print("!!Missing indices: ", list(missing_labels.index))
        if len(missing_labels) > 0:
            print("Removing null")
            df=df[~df['llm_label_raw'].isnull()]
       
        try:
            if os.path.exists(os.path.join(d, 'argument.txt')):
                args=open(os.path.join(d, 'argument.txt')).read().strip().split('\n')
                args=[a.split(':') for a in args]
                args={a[0]:a[1] for a in args}
            elif os.path.exists(os.path.join(d, 'argument_reload.txt')):
                args=open(os.path.join(d, 'argument_reload.txt')).read().strip().split('\n')
                args=[a.split(':') for a in args]
                args={a[0]:a[1] for a in args}
            else:
                logs=open(os.path.join(d, 'log.txt')).read().strip().split('\n')
                #User Prompt: generic
                #System Prompt: simple
                args=dict()
                args['Model']=[k for k in logs if k.startswith('Model name')][0].split(':')[1].strip()
                args['Dataset']=[k for k in logs if k.startswith('Benchmark')][0].split(':')[1].strip()
                args['prompt_type']=[k for k in logs if k.startswith('User Prompt')]
                args['system_prompt_type']= [k for k in logs if k.startswith('System Prompt')]
                if len(args['prompt_type']) == 0:
                    for k in mapper:
                        if k in d:
                            args['system_prompt_type']=mapper[k][0]
                            args['prompt_type']=mapper[k][1]
                            break
                else:
                    args['prompt_type']=args['prompt_type'][0].split(':')[1].strip()
                    args['system_prompt_type']=args['system_prompt_type'][0].split(':')[1].strip()

        except Exception as e:
            print("error:", d)
            print(e)
            continue
        if (args['system_prompt_type'], args['prompt_type']) not in prompts:
            continue
        if args['Dataset'] not in datasets:
            continue
        all_results[d]=[df, args]
        #df.to_csv(os.path.join(d, 'cache.csv'))
        
    return all_results

def get_max_metrics_per_dataset(all_results_df, datasets):
    max_metrics = dict()
    for ds in datasets:
        max_metrics[ds] = dict()
        for d in all_results_df:
            if all_results_df[d][1]['Dataset'] == ds:
                metrics = compute_precision_recall_accuracy(all_results_df[d][0], "true_label", "llm_label")
                max_metrics[ds]['accuracy'] = max(max_metrics[ds].get('accuracy', 0), metrics['accuracy'])
                max_metrics[ds]['F1'] = max(max_metrics[ds].get('F1', 0), metrics['F1'])


    return max_metrics

def gen_table(all_results_df, lang, models):
    model_names=[all_results_df[k][1]['Model'] for k in all_results_df]
    #model_seq=['gpt-4', 'gpt-3.5-turbo', 'codellama-34b-instruct', 'codellama-13b-instruct', 'codellama-7b-instruct']
    model_seq = models
    prompt_seq=[('simple','generic'), ('generic', 'generic'), 
                ('simple', 'cwe_specific'), ('generic', 'cwe_specific'), ('dataflow_steps', 'cwe_specific'),     ('generic', 'cpp_few_shot'), ('generic', 'java_few_shot'), ('cot', 'zero_shot_cot_cwe'),
                ('cot', 'zero_shot_cot')]
    dataset_seq = ['owasp', 'juliet-java-1.3', 'cvefixes-java-method', 'juliet-cpp-1.3', 'cvefixes-c-cpp-method']
    if lang == "java":
        dataset_seq = ['owasp', 'juliet-java-1.3', 'cvefixes-java-method']
    elif lang == "cpp":
        dataset_seq = ['juliet-cpp-1.3', 'cvefixes-c-cpp-method']
    else:
        dataset_seq = ['owasp', 'juliet-java-1.3', 'cvefixes-java-method', 'juliet-cpp-1.3', 'cvefixes-c-cpp-method']
    entries=[]
    headers=["Model", "Prompt"]   
    for d in dataset_seq:
        headers.extend(["{}".format(dataset_map[d]), "", "", ""])

    max_metrics = get_max_metrics_per_dataset(all_results_df, dataset_seq)

    metrics_header=["", ""]
    metrics_header.extend(["C", "Acc", "P", "R", "F1"]*len(dataset_seq))
    entries.append(metrics_header)
    for m in model_seq:  
        for prompt in prompt_seq:                   
            entry=[]
            entry.append(model_name_map[m])
            entry.append(prompt_type_map[prompt])
            for data in dataset_seq:
                res=[all_results_df[k][0] for k in all_results_df 
                     if all_results_df[k][1]['Model'] == m 
                     and all_results_df[k][1]['prompt_type'] == prompt[1] 
                     and all_results_df[k][1]['system_prompt_type'] == prompt[0] 
                     and all_results_df[k][1]['Dataset'] == data]
                assert len(res)<=1, (m, data, prompt)
                if len(res) == 0:
                    entry.append('-')
                    entry.append('-')
                    entry.append('-')
                    entry.append('-')
                    entry.append('-')
                else:
                    df=res[0]
                    metrics= compute_precision_recall_accuracy(df, "true_label", "llm_label")
                    entry.append(len(df))
                    if abs(metrics['accuracy'] - max_metrics[data]['accuracy']) <= 0.01:
                        entry.append( "\\cellhl{" + format(metrics['accuracy'], '.2f')+"}")
                    else:
                        entry.append(format(metrics['accuracy'], '.2f'))
                    entry.append(format(metrics['precision'], '.2f'))
                    entry.append(format(metrics['recall'], '.2f'))
                    if abs(metrics['F1'] - max_metrics[data]['F1']) <= 0.01:
                        entry.append( "\\cellhl{" + format(metrics['F1'], '.2f')+"}")
                    else:
                        entry.append(format(metrics['F1'], '.2f'))
            if entry.count('-') == len(entry) - 2:
                continue
            
            entries.append(entry)
    return entries, headers

def gen_table_cwe(all_results_df, models):
    top25=open('utils/cwe_top_25.txt').read().strip().split('\n')
    cwe_seq=[f"CWE-{cwe}" for cwe in top25]
    model_names=[all_results_df[k][1]['Model'] for k in all_results_df]
    model_seq = models
    prompt_seq=[('simple','generic'), ('generic', 'generic'), 
                ('simple', 'cwe_specific'), ('generic', 'cwe_specific'), ('dataflow_steps', 'cwe_specific')]
    dataset_seq = ['owasp', 'juliet-java-1.3', 'cvefixes-java-method', 'juliet-cpp-1.3', 'cvefixes-c-cpp-method']
    entries=[]
    headers=["Model", "Prompt"]   
    for d in dataset_seq:
        headers.extend(["{}".format(dataset_map[d]), "", "", ""])

    cwe_metrics = dict()

    metrics_header=["", ""]
    metrics_header.extend(["C", "Acc", "P", "R", "F1"]*len(dataset_seq))
    entries.append(metrics_header)
    for m in model_seq:  
        cwe_metrics[m] = dict()
        for prompt in prompt_seq: 
            cwe_metrics[m][prompt] = dict()                  
            entry=[]
            entry.append(model_name_map[m])
            entry.append(prompt_type_map[prompt])
            for data in dataset_seq:
                cwe_metrics[m][prompt][data] = dict()
                res=[all_results_df[k][0] for k in all_results_df 
                     if all_results_df[k][1]['Model'] == m 
                     and all_results_df[k][1]['prompt_type'] == prompt[1] 
                     and all_results_df[k][1]['system_prompt_type'] == prompt[0] 
                     and all_results_df[k][1]['Dataset'] == data]
                assert len(res)<=1, (m, data, prompt)
                if len(res) == 0:
                    entry.append('-')
                    entry.append('-')
                    entry.append('-')
                    entry.append('-')
                    entry.append('-')
                else:
                    df=res[0]
                    for cwe in top25:
                        cwe_df = df[df["true_cwe"] == cwe]
                        if len(cwe_df) == 0:
                            continue
                        cwe_metrics[m][prompt][data][cwe] = compute_precision_recall_accuracy(cwe_df, "true_label", "llm_label")
                        cwe_metrics[m][prompt][data][cwe]['support'] = len(cwe_df)

 
            entries.append(entry)
    return cwe_metrics

def process_codeql():
    import ast
    codeql_results = dict()   
    datasets = [ "juliet-java-1.3", "juliet-cpp-1.3", "owasp" ]
    for ds in datasets:
        codeql_results[ds] = dict()
        df=pd.read_csv(f"shared/v2/study_results_v2/codeql_final_metrics/{ds}/vulnerability_detection_metrics.csv", header=0)
        for i, row in df.iterrows():
            #codeql_results[row['Model']] = row['F1']
            # index true label false label
            if row["Id"] == 'All':
                continue
            for i in ast.literal_eval(row["TP"]):
                codeql_results[ds][i] = dict()
                codeql_results[ds][i]["true_label"] = True
                codeql_results[ds][i]["codeql_label"] = True
                codeql_results[ds][i]["true_cwe"] = row["Id"].split("‑")[-1]
            for i in  ast.literal_eval(row["FP"]):
                codeql_results[ds][i] = dict()
                codeql_results[ds][i]["true_label"] = False
                codeql_results[ds][i]["codeql_label"] = True
                codeql_results[ds][i]["true_cwe"] = row["Id"].split("‑")[1]
            for i in  ast.literal_eval(row["FN"]):
                codeql_results[ds][i] = dict()
                codeql_results[ds][i]["true_label"] = True
                codeql_results[ds][i]["codeql_label"] = False
                codeql_results[ds][i]["true_cwe"] = row["Id"].split("‑")[1]
            for i in  ast.literal_eval(row["TN"]):
                codeql_results[ds][i] = dict()
                codeql_results[ds][i]["true_label"] = False
                codeql_results[ds][i]["codeql_label"] = False
                codeql_results[ds][i]["true_cwe"] = row["Id"].split("‑")[1]
        codeql_results[ds] = [pd.DataFrame.from_dict(codeql_results[ds], orient="index"), None]
    filter_by_indices(codeql_results)
    return codeql_results


        
def plot_cwe_data(cwe_metrics):
    models = ['gpt-4', 'gpt-3.5-turbo', 'codellama-34b-instruct', 'codellama-13b-instruct', 'codellama-7b-instruct']
    prompt = ('dataflow_steps', 'cwe_specific')
    import matplotlib.pyplot as plt
    # save plot for each dataset/model combination
    for model in models:
        for ds in cwe_metrics[model][prompt]:
            cwe_ds = cwe_metrics[model][prompt][ds]
            all_cwes = sorted(list(cwe_ds.keys()), key=int)
            all_cwes = [ cwe for cwe in all_cwes if cwe_ds[cwe]['support'] >= 10 ] # only plot cwes with support >= 10

            all_cwe_acc = [cwe_ds[cwe]['accuracy_balanced'] for cwe in all_cwes]
            all_cwe_f1 = [cwe_ds[cwe]['F1'] for cwe in all_cwes]
            for cwe in all_cwes:
                print(model, ds, f"CWE-{cwe}", cwe_ds[cwe]['support'], cwe_ds[cwe]['accuracy'], cwe_ds[cwe]['F1'])
            # plot accuracy and f1 side by side per cwe
            bar_width = 0.35
            if 'cvefixes' in ds:
                plt.rcParams.update({'font.size': 16})
                fig, ax = plt.subplots(figsize=(12, 6))
                font_size = 16
            
            else:
                plt.rcParams.update({'font.size': 13})
                fig, ax = plt.subplots(figsize=(6, 4))
                font_size = 13
                
            index=np.arange(len(all_cwes))

            bar1 = ax.bar(index, all_cwe_acc, bar_width, color='#ffb55a' , alpha=1, label='Accuracy', edgecolor='black')
            bar2 = ax.bar(index+bar_width, all_cwe_f1, bar_width, color='#7eb0d5', alpha=1, label='F1', edgecolor='black')
            ax.set_ylabel('')
            # set y limit to 0 1
            ax.set_ylim(0, 1)
            ax.set_xticks(index + bar_width / 2)
            ax.set_xticklabels(["CWE-"+cwe for cwe in all_cwes], rotation=45)        
            ax.legend(loc='upper center', bbox_to_anchor=(0.5, 1.2), ncol=2, fontsize=font_size)
            plt.tight_layout()
            plt.savefig(os.path.join("shared/v2/study_results_v2_plots", f'cwe_metrics_{model}_{ds}.png'))

def plot_codeql_results(codeql_results_df, all_results_df):
    entries = []
    prompt = ('dataflow_steps', 'cwe_specific')
    headers = ["", "A", "P", "R", "F1",  "A", "P", "R", "F1",  "A", "P", "R", "F1" ]
    
    for ds in [ 'owasp', 'juliet-java-1.3', 'juliet-cpp-1.3' ]:
        codeql_df = codeql_results_df[ds][0]
        for model in [ 'gpt-4']:
            print(model, ds)
            model_df = [k for k in all_results_df.values() if k[1]["Model"] == model and k[1]["Dataset"] == ds and (k[1]['system_prompt_type'], k[1]['prompt_type']) == prompt ][0][0]
            #model_df = all_results_df[model_df][0]
            codeql_metrics = compute_precision_recall_accuracy(codeql_df, "true_label", "codeql_label")
            model_metrics = compute_precision_recall_accuracy(model_df, "true_label", "llm_label")
            entry = [f"{dataset_map[ds]}", 
                     codeql_metrics['accuracy'], codeql_metrics['precision'], codeql_metrics['recall'], codeql_metrics['F1'],
                     model_metrics['accuracy'], model_metrics['precision'], model_metrics['recall'], model_metrics['F1']
                    ]
            entries.append(entry)

    print(
        tabulate.tabulate(
            entries,
            headers=headers,
            tablefmt="latex_raw",
            floatfmt=".2f"
    )
    )

    cwes = dict()
    cwes['owasp'] = codeql_results_df['owasp'][0]['true_cwe'].unique()
    cwes['juliet-java-1.3'] = codeql_results_df['juliet-java-1.3'][0]['true_cwe'].unique()
    cwes['juliet-cpp-1.3'] = codeql_results_df['juliet-cpp-1.3'][0]['true_cwe'].unique()
    entries = []
    headers = ["Dataset", "CWE", "A", "P", "R", "F1",  "A", "P", "R", "F1" ]
  
    for ds in [ 'owasp', 'juliet-java-1.3', 'juliet-cpp-1.3' ]:
       
        codeql_df = codeql_results_df[ds][0]
        for cwe in cwes[ds]:            
            for model in [ 'gpt-4']:
                print(model, ds, cwe)
                model_df = [k for k in all_results_df.values() if k[1]["Model"] == model and k[1]["Dataset"] == ds and (k[1]['system_prompt_type'], k[1]['prompt_type']) == prompt ][0][0]
                codeql_metrics = compute_precision_recall_accuracy(codeql_df[codeql_df['true_cwe'] == cwe], "true_label", "codeql_label")
                model_metrics = compute_precision_recall_accuracy(model_df[model_df['true_cwe'] == cwe], "true_label", "llm_label")
                entry = [f"{dataset_map[ds]}",  f"CWE-{cwe}",
                         codeql_metrics['accuracy'], codeql_metrics['precision'], codeql_metrics['recall'], codeql_metrics['F1'],
                         model_metrics['accuracy'], model_metrics['precision'], model_metrics['recall'], model_metrics['F1']
                        ]
                entries.append(entry)

    print(
        tabulate.tabulate(
            entries,
            headers=headers,
            tablefmt="latex_raw",
            floatfmt=".2f"
    )
    )

    detected = dict()
    for ds in [ 'owasp', 'juliet-java-1.3', 'juliet-cpp-1.3' ]:
        codeql_df = codeql_results_df[ds][0]
        codeql_df = codeql_df[codeql_df['true_label'] == True]
        model_df = [k for k in all_results_df.values() if k[1]["Model"] == 'gpt-4' and k[1]["Dataset"] == ds and (k[1]['system_prompt_type'], k[1]['prompt_type']) == prompt ][0][0]
        model_df = model_df[model_df['true_label'] == True]
        codeql_detected = codeql_df[(codeql_df['codeql_label'] == True)].index.astype(str)
        model_detected = model_df[(model_df['llm_label'] == True)].index.astype(str)
        #detected[ds] = (codeql_detected, model_detected)
        print(ds)
        print("Both", len(set(codeql_detected).intersection(set(model_detected))))
        print("Only CodeQL", len(set(codeql_detected) - set(model_detected)))
        print("Only Model", len(set(model_detected) - set(codeql_detected)))
        print("None", len(set(codeql_df.index.astype(str)) - set(codeql_detected) - set(model_detected)))
    for ds in ['owasp', 'juliet-java-1.3', 'juliet-cpp-1.3']:
        for cwe in cwes[ds]:
            codeql_df = codeql_results_df[ds][0]
            codeql_df = codeql_df[codeql_df['true_cwe'] == cwe]
            codeql_df = codeql_df[codeql_df['true_label'] == True]
            model_df = [k for k in all_results_df.values() if k[1]["Model"] == 'gpt-4' and k[1]["Dataset"] == ds and (k[1]['system_prompt_type'], k[1]['prompt_type']) == prompt ][0][0]
            model_df = model_df[model_df['true_cwe'] == cwe]
            model_df = model_df[model_df['true_label'] == True]
            codeql_detected = codeql_df[(codeql_df['codeql_label'] == True)].index.astype(str)
            model_detected = model_df[(model_df['llm_label'] == True)].index.astype(str)
            print(ds, cwe)
            print(f"{cwe} Both", len(set(codeql_detected).intersection(set(model_detected))))
            print(f"{cwe} Only CodeQL", len(set(codeql_detected) - set(model_detected)))
            print(f"{cwe} Only Model", len(set(model_detected) - set(codeql_detected)))
            print(f"{cwe} None", len(set(codeql_df.index.astype(str)) - set(codeql_detected) - set(model_detected)))
            



    
if __name__ == "__main__":
    #python utils/metrics_table.py java|cpp [filter by indices: 1|0]
    use_cache=sys.argv[2] == "1" if len(sys.argv) > 2 else False
    models = ['mistral-codestral-22b', 'deepseekcoder-7b', 'deepseekcoder-v2-15b', 'deepseekcoder-33b', 'llama-3.1-8b', 'llama-3.1-70b', 'codellama-34b-instruct', 'codellama-70b-instruct',
              'qwen2.5-14b', 'qwen2.5-coder-7b', 'qwen2.5-coder-1.5b', 'qwen2.5-32b']
    prompts = [('simple','generic'), ('generic', 'generic'), 
               ('simple', 'cwe_specific'), ('generic', 'cwe_specific'), ('dataflow_steps', 'cwe_specific'),  ('generic', 'cpp_few_shot'), ('generic', 'java_few_shot'), ('cot', 'zero_shot_cot_cwe'),  ('cot', 'zero_shot_cot')]
    datasets = ['owasp', 'juliet-java-1.3', 'cvefixes-java-method', 'juliet-cpp-1.3', 'cvefixes-c-cpp-method']

    all_results_df = process('./shared/v2/study_results_v2/', sys.argv[1], models, prompts, datasets, use_cache) # skip for gpt
    filter_by_indices(all_results_df)
    
    entries, headers = gen_table(all_results_df, sys.argv[1], models)
    
    print(
        tabulate.tabulate(
            entries,
            headers=headers,
            tablefmt="orgtbl",
            floatfmt=".2f"
        )
    )
    print(
        tabulate.tabulate(
            entries,
            headers=headers,
            tablefmt="latex_raw",
            floatfmt='.2f'
        )
    )

       

       
