from transformers import AutoTokenizer, AutoModelForCausalLM
import transformers
import torch
import models.config as config
from utils.mylogger import MyLogger
import os
from models.llm import LLM
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "max_split_size_mb:256"

_model_name_map = {
    "codellama-70b-instruct": 'codellama/CodeLlama-70b-Instruct-hf',
    "codellama-34b": 'codellama/CodeLlama-34b-hf',
    "codellama-34b-python": 'codellama/CodeLlama-34b-Python-hf',
    "codellama-34b-instruct": 'codellama/CodeLlama-34b-Instruct-hf',
    "codellama-13b-instruct": 'codellama/CodeLlama-13b-Instruct-hf',
    "codellama-7b-instruct": 'codellama/CodeLlama-7b-Instruct-hf', 
}

class CodeLlamaModel(LLM):
    def __init__(self, model_name, logger: MyLogger, **kwargs):
        super().__init__(model_name, logger, _model_name_map, **kwargs)
        self.terminators = [
                self.pipe.tokenizer.eos_token_id,
        ]


    def predict(self, main_prompt, batch_size=0, no_progress_bar=False):
        if batch_size > 0:
            prompts = [self.pipe.tokenizer.apply_chat_template(p, tokenize=False, add_generation_prompt=True) for p in main_prompt]
            self.model_hyperparams['temperature']=0.01
            return self.predict_main(prompts, batch_size=batch_size, no_progress_bar=no_progress_bar)
        else:
            prompt = self.pipe.tokenizer.apply_chat_template(
            main_prompt, 
            tokenize=False, 
            add_generation_prompt=True
            )
            l=len(self.tokenizer.tokenize(prompt))
            self.log("Prompt length:" +str(l))
            limit=16000 if self.kwargs["max_input_tokens"] is None else self.kwargs["max_input_tokens"]
            if l > limit:
                return "Too long, skipping: "+str(l)
            if 'dataflow' in self.kwargs['system_prompt_type']:
                print(">Setting max tokens to ", 2048)
                self.model_hyperparams['max_new_tokens']=2048
            self.model_hyperparams['temperature']=0.01
            return self.predict_main(prompt, no_progress_bar=no_progress_bar)

if __name__ == '__main__':
    system="You are a security researcher, expert in detecting vulnerabilities. Provide response in following format: 'vulnerability: <YES/NO> | vulnerability type: <CWE_ID> | lines of code: <VULNERABLE_LINES_OF_CODE>"
    from data.bigvul import BigVul
    bigvul = BigVul(os.path.join(config.config['DATA_DIR_PATH'] ,"MSR_20_Code_vulnerability_CSV_Dataset"))
    id, row = bigvul.get_next()

    codellama_model = CodeLlamaModel(None)
    print(">>>Running CodeLlama")
    print(">>>ID:", str(id))
    print(codellama_model.predict(system, 
                                  f"Can you find any vulnerability in this code? ```{row}```")
    )
