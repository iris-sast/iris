from transformers import AutoTokenizer, AutoModelForCausalLM
import transformers
import torch
import models.config as config
from utils.mylogger import MyLogger
import os
from models.llm import LLM
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "max_split_size_mb:64"

_model_name_map = {
    "codegen-16b-multi": "Salesforce/codegen-16B-multi",
    "codegen25-7b-instruct": "Salesforce/codegen25-7b-instruct",
    "codegen25-7b-multi": "Salesforce/codegen25-7b-multi"
}

class CodegenModel(LLM):
    def __init__(self, model_name, logger: MyLogger, **kwargs):
        super().__init__(model_name, logger, _model_name_map, **kwargs)
   
    def predict(self, main_prompt): 
        # assuming 0 is system and 1 is user
        system_prompt = main_prompt[0]['content']
        user_prompt = main_prompt[1]['content']
        if 'instruct' in self.model_name:
            prompt = f"Instruction: {system_prompt}\\n Input: \\n {user_prompt}\\n Output:\\n"
        else:
            prompt = f"Input: \\n {user_prompt}\\n Output:\\n"
        return self.predict_main(prompt)
