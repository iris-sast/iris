from transformers import AutoTokenizer, AutoModelForCausalLM, AutoModelForSeq2SeqLM
import transformers
import torch
import models.config as config
from utils.mylogger import MyLogger
import os
from models.llm import LLM
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "max_split_size_mb:64"

_model_name_map = {
    "codet5p-16b-instruct": "Salesforce/instructcodet5p-16b",
    "codet5p-16b": "Salesforce/codet5p-16b",
    "codet5p-6b": "Salesforce/codet5p-6b",
    "codet5p-2b": "Salesforce/codet5p-2b"
}

class CodeT5PlusModel():
    def __init__(self, model_name, logger: MyLogger, **kwargs):
        self.model_name=model_name
        self.tokenizer = AutoTokenizer.from_pretrained(_model_name_map[model_name])
        self.model = AutoModelForSeq2SeqLM.from_pretrained(_model_name_map[model_name],
                                                      torch_dtype=torch.float16,
                                                      low_cpu_mem_usage=True,
                                                      trust_remote_code=True,
                                                      device_map="auto"
        )     
   
    def predict(self, main_prompt): 
        # assuming 0 is system and 1 is user
        system_prompt = main_prompt[0]['content']
        user_prompt = main_prompt[1]['content']
        if 'instruct' in self.model_name:
            prompt = f"Instruction: {system_prompt}\\n Input:\\n {user_prompt} \\n Output:\\n"
        else:
            prompt = f"Input:\\n {user_prompt} \\n Output:\\n"
        encoding = self.tokenizer(prompt, return_tensors="pt").to("cuda")
        if len(encoding) > 1000:
            return prompt, "Skipping, too long " + str(len(encoding))
        encoding['decoder_input_ids'] = encoding['input_ids'].clone()
        outputs = self.model.generate(**encoding, max_length=2000)
        return prompt, self.tokenizer.decode(outputs[0], skip_special_tokens=True)
