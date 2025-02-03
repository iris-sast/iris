import openai
import os
from utils.mylogger import MyLogger
from utils.prompt_utils import generate_message_list, generate_validation_message_list
import time

_OPENAI_DEFAULT_PARAMS = {"temperature": 0, "n": 1, "max_tokens": 1024, "stop": ""}
_DELAY_SECS = 5

class OpenAIModel:
    def __init__(self, logger: MyLogger, model_name="gpt-4", **kwargs):
        if logger is None:
            self.log = lambda x: print(x)
        else:
            self.log = lambda x: logger.log(x)
        self.model_id = model_name
        self.model_params = _OPENAI_DEFAULT_PARAMS
        self.kwargs = kwargs
        self.log(f"Model: {model_name}")
        self.log(f"Model params: {self.model_params}")

        if ("openai_api_key" in kwargs) and (kwargs["openai_api_key"] is not None):
            openai.api_key = kwargs["openai_api_key"]
        else:
            openai.api_key = os.getenv("OPENAI_API_KEY")

    def call_openai(self, prompt, n_tries=5):
        while n_tries > 0:
            try:
                output = openai.ChatCompletion.create(
                    model=self.model_id, messages=prompt, **self.model_params
                )
                # Only return the first response
                return output["choices"][0]["message"]
            except Exception as e:
                n_tries -= 1
                error_message = "OpenAI call failed with Exception: ", str(e)
                self.log(error_message)
                # Add a time delay to recover the rate limit, if any
                time.sleep(_DELAY_SECS)
                # Report this as an error
                if n_tries == 0:
                    return {"role": "error", "content": error_message}

    def get_prompt(self, snippet, prompt_cwe):
        cwe_specific = (
            "cwe_specific" in self.kwargs["prompting_technique"]
            or "cwe_specific" in self.kwargs['prompt_type']
            or "cwe_specific" in self.kwargs['system_prompt_type']
        )
        # Prompt with item CWE if asked
        prompt_cwe = prompt_cwe if cwe_specific else -1
        self.log(f"Prompting technique: {self.kwargs['prompting_technique']}")
        self.log(f"User Prompt: {self.kwargs['prompt_type']}")
        self.log(f"System Prompt: {self.kwargs['system_prompt_type']}")
        self.log(f"Prompt CWE: {prompt_cwe}")
            
        return generate_message_list(
            prompting_technique=self.kwargs["prompting_technique"],
            snippet=snippet,
            prompt_cwe=prompt_cwe,
            user_prompt=self.kwargs['prompt_type'],
            system_prompt=self.kwargs['system_prompt_type'],
        )

    def predict(self, message):
        # Self validate results (using responses from the previous run)
        # We don't want to call the model with the previous prompts again
        if "validate_results_from_dir" in self.kwargs and self.kwargs["validate_results_from_dir"] is not None:
            main_prompt = generate_validation_message_list(message["id"], self.kwargs["validate_results_from_dir"])
            response = self.call_openai(main_prompt)
            pred = "" if response["role"] == "error" else response["content"]
            main_prompt.append({"role": "assistant", "content": pred})
            return self._stringify_chat(main_prompt), pred
        
        snippet = message["snippet"]
        prompt_cwe = message["prompt_cwe"]
        main_prompt = self.get_prompt(snippet=snippet, prompt_cwe=prompt_cwe)
        # Maintain a running prompt with the chat history
        running_prompt = []
        for prompt in main_prompt:
            running_prompt.append(prompt)
            if prompt["role"] == "user":
                # Predict when a user prompt is provided
                response = self.call_openai(running_prompt)
                if response["role"] == "error":
                    # An empty string in the prediction will re-run the experiment on the sample after reload
                    running_prompt.append({"role": "assistant", "content": ""})
                    break

                time.sleep(_DELAY_SECS)
                # Store the chat history
                running_prompt.append(response)
                # Do not continue the chat if an error occurred
                
        pred = running_prompt[-1]["content"]
        return self._stringify_chat(running_prompt), pred

    def _stringify_chat(self, chat_history):
        prompt_str = ""
        # Skip the final prediction
        for prompt in chat_history[:-1]:
            prompt_str += prompt["role"].upper() + "\n"
            prompt_str += prompt["content"]
            prompt_str += "\n-------------------\n"
        return prompt_str
