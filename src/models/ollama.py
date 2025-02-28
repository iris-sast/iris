import os
import ollama
from tqdm.contrib.concurrent import thread_map

from src.models.llm import LLM
from src.utils.mylogger import MyLogger

_model_name_map = {
    "ollama-qwen-coder": "qwen2.5-coder:latest",
    "ollama-qwen": "qwen2.5:32b",
    "ollama-llama3": "llama3.2:latest",
    "ollama-deepseek-32b": "deepseek-r1:32b",
    "ollama-deepseek-7b": "deepseek-r1:latest",
}

# default model parameters, add or modify according to your needs
# see https://github.com/ollama/ollama/blob/main/docs/modelfile.md#valid-parameters-and-values
_OLLAMA_DEFAULT_OPTIONS = {
    "temperature": 0.8,
    "num_predict": -1,
    "stop": None,
    "seed": 0,
}


class OllamaModel(LLM):
    def __init__(self, model_name, logger: MyLogger, **kwargs):
        super().__init__(model_name, logger, _model_name_map, **kwargs)
        if host := os.environ.get("OLLAMA_HOST"):
            self.client = ollama.Client(host=host)
        else:
            self.log.error("Please set OLLAMA_HOST environment variable")
        # TODO: https://github.com/ollama/ollama/issues/2415
        # self.logprobs = None
        for k in _OLLAMA_DEFAULT_OPTIONS:
            if k in kwargs:
                _OLLAMA_DEFAULT_OPTIONS[k] = kwargs[k]

    def predict(self, prompt, batch_size=0, no_progress_bar=False):
        if batch_size == 0:
            return self._predict(prompt)
        args = range(0, len(prompt))
        responses = thread_map(
            lambda x: self._predict(prompt[x]),
            args,
            max_workers=batch_size,
            disable=no_progress_bar,
        )
        return responses

    def _predict(self, main_prompt):
        # assuming 0 is system and 1 is user
        system_prompt = main_prompt[0]["content"]
        user_prompt = main_prompt[1]["content"]
        prompt = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        try:
            response = self.client.chat(
                model=self.model_id,
                messages=prompt,
                options=_OLLAMA_DEFAULT_OPTIONS,
            )
        except ollama.ResponseError as e:
            print("Ollama Response Error:", e.error)
            return None

        return response.message.content
