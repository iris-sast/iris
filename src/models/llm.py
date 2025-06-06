from transformers import AutoTokenizer, AutoModelForCausalLM, AutoModelForSeq2SeqLM
import transformers
import torch
import models.config as config
from utils.mylogger import MyLogger
import os
import tqdm

class LLM:
    def __init__(self, model_name, logger: MyLogger, model_name_map, **kwargs):
        if logger is None:
            self.log =lambda x: print(x)
        else:
            self.log = lambda x: logger.log(x)
        self.model_name_map = model_name_map
        self.kwargs = kwargs
        self.model_name = model_name

        try:
            self.model_id = model_name_map[model_name.lower()]
            self.model_hyperparams = config.config['DEFAULT_PARAMS']
            for k in self.model_hyperparams:
                if k in self.kwargs:
                    self.model_hyperparams[k] = self.kwargs[k]
        except:
            self.log(">>>Model not found:" + model_name)
            self.log("Valid keys: ")
            self.log(model_name_map.keys())

            exit(1)

        # nothing else needed if calling gpt
        if model_name.lower().startswith("gpt"):
            return
        # nothing else needed if calling ollama api
        elif model_name.lower().startswith("ollama"):
            return
        # nothing else needed if calling together AI
        elif "-tai" in model_name.lower():
            return

        if model_name.lower().startswith('codet5'):
            model_loader=AutoModelForSeq2SeqLM
            self.log(">>>Loading CodeT5 model with Seq2SeqLM")
        else:
            self.log(">>>Loading LLM model with CausalLM")
            model_loader=AutoModelForCausalLM

        self.tokenizer = AutoTokenizer.from_pretrained(self.model_id)
        self.log(">>>Loading model")
        if kwargs.get('vllm', None) is not None:
            self.log(">>>Using vLLM")
            from vllm import LLM
            self.model=LLM(model=self.model_id, tensor_parallel_size=8, trust_remote_code=True, gpu_memory_utilization=0.8, max_context_len_to_capture=4096, max_seq_len=4096)


        elif kwargs.get('bits', None) is not None:
            if kwargs['bits'] == 8:
                self.model = model_loader.from_pretrained(
                    self.model_id,
                    torch_dtype=torch.float16,
                    device_map="auto",
                    load_in_8bit=True
                    )
            elif kwargs['bits'] == 4:
                  self.model = model_loader.from_pretrained(
                    self.model_id,
                    torch_dtype=torch.float16,
                    device_map="auto",
                    load_in_4bit=True
                    )
            else:
                self.log(">>>Invalid bit width: ", kwargs['bits'])
                exit(1)
        elif kwargs.get('flash2', None) is not None:
            self.model = model_loader.from_pretrained(
                self.model_id,
                torch_dtype=torch.float16,
                device_map="auto", attn_implementation="flash_attention_2")
        else:
            self.model = model_loader.from_pretrained(
                self.model_id,
                torch_dtype=torch.float16,
                device_map="auto",
                trust_remote_code=True)


        # for multi-gpu
        #if 'mixtral' not in self.model_name.lower() and 'gemma' not in self.model_name.lower():
        #    self.model = self.model.to_bettertransformer()

        self.pipe = transformers.pipeline(
            "text-generation",
            model=self.model,
            tokenizer=self.tokenizer
        )
        self.pipe.tokenizer.pad_token_id = self.pipe.model.config.eos_token_id
        self.pipe.tokenizer.padding_side = 'left'


    def get_model_names(self):
        return list(model_name_map.keys())

    def predict_main(self, prompt, batch_size=0, no_progress_bar=False):
        if self.kwargs.get('vllm', None):
            from vllm import SamplingParams
            params=SamplingParams(temperature=self.model_hyperparams['temperature'], top_p=self.model_hyperparams['top_p'], max_tokens=self.model_hyperparams['max_new_tokens'])
            output = self.model.generate(prompt, params)
            return output.outputs[0].text

        if self.kwargs.get('flash'):
            with torch.backends.cuda.sdp_kernel(enable_flash=True, enable_math=False, enable_mem_efficient=False):
                torch.cuda.synchronize()
                print(">>flash enabled", torch.backends.cuda.flash_sdp_enabled())
                # input_ids=self.tokenizer(prompt, return_tensors="pt").input_ids.to('cuda')
                print("params", self.model_hyperparams['max_new_tokens'])
                # output=self.model.generate(inputs=input_ids, max_new_tokens=self.model_hyperparams['max_new_tokens'], temperature=self.model_hyperparams['temperature'], top_p=self.model_hyperparams['top_p'])
                # print(input_ids)
                # print(input_ids.shape, len(output[0]))
                # ids=output[0][input_ids.shape[1]:]
                # output=self.tokenizer.decode(ids, skip_special_tokens=True)
                # print(output)
                # return prompt, output
                output = self.pipe(
                    prompt,
                    max_new_tokens=self.model_hyperparams['max_new_tokens'],
                    temperature=self.model_hyperparams['temperature'],
                    top_p=self.model_hyperparams['top_p'],
                    pad_token_id=self.tokenizer.eos_token_id,
                    #eos_token_id=self.tokenizer.eos_token_id,
                    return_full_text=False
                    #skip_special_tokens=True
                )
        else:
            if batch_size > 0:
                output = []
                from torch.utils.data import Dataset
                class ListDataset(Dataset):
                    def __init__(self, original_list):
                        self.original_list = original_list
                    def __len__(self):
                        return len(self.original_list)
                    def __getitem__(self, i):
                        return self.original_list[i]
                #from torch.utils.data import DataLoader
                # mydataset=ListDataset(prompt)
                # data_loader = DataLoader(mydataset, batch_size=batch_size, shuffle=False)

                #for i in tqdm.tqdm(range(0, len(prompt), batch_size), disable=no_progress_bar):
                # pbar = tqdm.tqdm(data_loader)
                # for i, prompt_b in enumerate(pbar):
                #     #prompt_b = prompt[i:i+batch_size]
                #     #mydataset = ListDataset(prompt_b)
                #     #print(mydataset.__dict__)
                #     result = self.pipe(prompt_b,
                #                        max_new_tokens=self.model_hyperparams['max_new_tokens'],
                #                        temperature=self.model_hyperparams['temperature'],
                #                        top_p=self.model_hyperparams['top_p'],
                #                        eos_token_id=self.terminators,
                #                        pad_token_id=self.tokenizer.eos_token_id,
                #                        #eos_token_id=self.tokenizer.eos_token_id,
                #                        return_full_text=False,
                #                        do_sample=False
                #                        )
                #     #print(result)
                #     output.extend([r[0]['generated_text'] for r in result])
                #     pbar.set_description(f"Processing Batch {i+1}/{len(data_loader)}, #Outputs : {len(output)}")
                    #print(len(output))

                mydataset=ListDataset(prompt)
                for result in tqdm.tqdm(self.pipe(mydataset,
                                                    max_new_tokens=self.model_hyperparams['max_new_tokens'],
                                                    temperature=self.model_hyperparams['temperature'],
                                                    top_p=self.model_hyperparams['top_p'],
                                                    eos_token_id=self.terminators,
                                                    pad_token_id=self.tokenizer.eos_token_id,
                                                    #eos_token_id=self.tokenizer.eos_token_id,
                                                    return_full_text=False,
                                                    #do_sample=False,
                                                    batch_size=batch_size), disable=no_progress_bar):

                    output.append(result)
                return [o[0]['generated_text'] for o in output]
            else:
                output = self.pipe(
                    prompt,
                    max_new_tokens=self.model_hyperparams['max_new_tokens'],
                    temperature=self.model_hyperparams['temperature'],
                    top_p=self.model_hyperparams['top_p'],
                    eos_token_id=self.terminators,
                    pad_token_id=self.tokenizer.eos_token_id,
                    #eos_token_id=self.tokenizer.eos_token_id,
                    return_full_text=False,
                    do_sample=False
                    )
                return output[0]['generated_text']



    @staticmethod
    def get_llm(model_name, kwargs, logger):
        if model_name.lower().startswith("codellama"):
            from models.codellama import CodeLlamaModel

            model = CodeLlamaModel(model_name, logger, **kwargs)
        elif model_name.lower().startswith("llama"):
            from models.llama import LlamaModel

            model = LlamaModel(model_name, logger, **kwargs)

        elif model_name.lower().startswith("wizardcoder"):
            from models.wizarcoder import WizardCoderModel

            model = WizardCoderModel(model_name, logger, **kwargs)
        elif model_name.lower().startswith("starcoder"):
            from models.starcoder import StarCoderModel

            model = StarCoderModel(model_name, logger, **kwargs)
        elif model_name.lower().startswith("codegen"):
            from models.codegen import CodegenModel

            model = CodegenModel(model_name, logger, **kwargs)
        # elif model_name.lower().startswith("gpt"):
        #     from models.openaimodels import OpenAIModel

        #     model = OpenAIModel(model_name=model_name, logger=logger, **kwargs)
        elif model_name.lower().startswith("codet5p"):
            from models.codet5 import CodeT5PlusModel

            model = CodeT5PlusModel(model_name=model_name, logger=logger, **kwargs)
        elif model_name.lower().startswith("mistral") or model_name.lower().startswith("mixtral"):
            from models.mistral import MistralModel
            model=MistralModel(model_name=model_name, logger=logger, **kwargs)
        elif model_name.lower().startswith("gpt"):
            from models.gpt import GPTModel
            model=GPTModel(model_name=model_name, logger=logger, **kwargs)
        elif model_name.lower().startswith("ollama"):
            from models.ollama import OllamaModel
            model = OllamaModel(model_name=model_name, logger=logger, **kwargs)
        elif model_name.lower().startswith("gemma"):
            from models.google import GoogleModel
            model=GoogleModel(model_name=model_name, logger=logger, **kwargs)
        elif model_name.lower().startswith("deepseek"):
            from models.deepseek import DeepSeekModel
            model=DeepSeekModel(model_name=model_name, logger=logger, **kwargs)
        elif model_name.lower().startswith("qwen"):
            from models.qwen import QwenModel
            model=QwenModel(model_name=model_name, logger=logger, **kwargs)

        elif model_name.lower().startswith("gemini"):
            from models.gemini import GeminiModel
            model=GeminiModel(model_name=model_name, logger=logger, **kwargs)

        else:
            logger.log(model_name + " not implemented")
            exit(1)
        return model
