from transformers import AutoTokenizer, AutoModelForCausalLM
import transformers
import torch
import models.config as config
from utils.mylogger import MyLogger
import os
from models.llm import LLM
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "max_split_size_mb:256"

_model_name_map = {
    "gemma-7b": 'google/gemma-7b',
    "gemma-7b-it": 'google/gemma-1.1-7b-it',
    "gemma-2b": 'google/gemma-2b',
    "gemma-2b-it": 'google/gemma-1.1-2b-it',
    "codegemma-7b-it" : 'google/codegemma-7b-it',
    "gemma-2-27b" : 'google/gemma-2-27b-it',
    "gemma-2-9b": 'google/gemma-2-9b-it'
}

class GoogleModel(LLM):
    def __init__(self, model_name, logger: MyLogger, **kwargs):
        super().__init__(model_name, logger, _model_name_map, **kwargs)
        self.terminators = [
                self.pipe.tokenizer.eos_token_id,
        ]

    def predict(self, main_prompt, batch_size=0, no_progress_bar=False):
        def rename(d):
            newd = dict()
            newd["role"]="user"
            newd["content"]=d[0]['content'] + '\n'+ d[1]['content']
            return [newd]
            
        if batch_size > 0:
            prompts = [self.pipe.tokenizer.apply_chat_template(rename(p), tokenize=False, add_generation_prompt=True) for p in main_prompt]
            self.model_hyperparams['temperature']=0.0
            return self.predict_main(prompts, batch_size=batch_size, no_progress_bar=no_progress_bar)
        else:
            prompt = self.pipe.tokenizer.apply_chat_template(
            main_prompt, 
            tokenize=False, 
            add_generation_prompt=True
            )
            self.model_hyperparams['temperature']=0.01
            return self.predict_main(prompt, no_progress_bar=no_progress_bar)
        # assuming 0 is system and 1 is user
        system_prompt = main_prompt[0]['content']
        user_prompt = main_prompt[1]['content']
        prompt = f"{system_prompt}\\n{user_prompt}"
        l=len(self.tokenizer.tokenize(prompt))
        self.log("Prompt length:" +str(l))
        limit=16000 if self.kwargs["max_input_tokens"] is None else self.kwargs["max_input_tokens"]
        if l > limit:
            return prompt, "Too long, skipping: "+str(l)
        if 'dataflow' in self.kwargs['system_prompt_type']:
            print(">Setting max tokens to ", 1024)
            self.model_hyperparams['max_new_tokens']=1024
        return self.predict_main(prompt)

if __name__ == '__main__':
    system="You are a security researcher, expert in detecting vulnerabilities. Provide response in following format: 'vulnerability: <YES/NO> | vulnerability type: <CWE_ID> | lines of code: <VULNERABLE_LINES_OF_CODE>"
    from data.bigvul import BigVul
    from data.cvefixes import CVEFixes
    #bigvul = BigVul(os.path.join(config.config['DATA_DIR_PATH'] ,"MSR_20_Code_vulnerability_CSV_Dataset"), logger=None)
    cvefixes=CVEFixes("cvefixes-c-cpp-method", logger=None).df
    #id, row = bigvul.get_next()
    row=cvefixes.iloc[0]['code']
    gemma_model = GoogleModel("gemma-7b-it", logger=None, max_input_tokens=1024, flash=False, system_prompt_type='')
    print(">>>Running Gemma")
    print(">>>ID:", str(id))
    model_input = [{"role": "system", "content": system}, {"role": "user", "content": row}]
    print(gemma_model.predict(model_input))
