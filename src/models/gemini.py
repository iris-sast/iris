# pip install google-generativeai

import models.config as config
from utils.mylogger import MyLogger
import os
from models.llm import LLM
import google.generativeai as genai
from tqdm.contrib.concurrent import thread_map

_model_name_map = {
    "gemini-1.5-pro": "gemini-1.5-pro-latest",
    "gemini-1.5-flash": "gemini-1.5-flash-latest",
    "gemini-pro": "gemini-pro",
    "gemini-pro-vision": "gemini-pro-vision",
    "gemini-1.0-pro-vision": "gemini-1.0-pro-vision-latest"
}
_GEMINI_DEFAULT_PARAMS = {"temperature": 0.4, "top_p": 1, "top_k": 32, "max_tokens": 2048 }

class GeminiModel(LLM):
    def __init__(self, model_name, logger: MyLogger, **kwargs):
        # https://aistudio.google.com/app/apikey
        if ("google_api_key" in kwargs) and (kwargs["google_api_key"] is not None):
            api_key = kwargs["google_api_key"]
        else:
            api_key = os.getenv("GOOGLE_API_KEY")
        genai.configure(api_key=api_key)
        self.logprobs = None
        for k in _GEMINI_DEFAULT_PARAMS:
            if k in kwargs:
                #print(f"Setting {k}:{kwargs[k]}")
                _GEMINI_DEFAULT_PARAMS[k] = kwargs[k]
        genai.GenerationConfig(max_output_tokens=_GEMINI_DEFAULT_PARAMS["max_tokens"],
                               temperature=_GEMINI_DEFAULT_PARAMS["temperature"],
                               top_p=_GEMINI_DEFAULT_PARAMS["top_p"],
                               top_k=_GEMINI_DEFAULT_PARAMS["top_k"])
        self.client = genai.GenerativeModel(model_name=model_name)

    def predict(self, prompt, batch_size=0, no_progress_bar=False):
        if batch_size == 0:
            return self._predict(prompt)
        args = range(0, len(prompt))
        responses = thread_map(
            lambda x: self._predict(prompt[x]),
            args,
            max_workers=batch_size,
            disable=no_progress_bar)
        return responses

    def _predict(self, main_prompt):
        # assuming 0 is system and 1 is user
        # https://www.googlecloudcommunity.com/gc/AI-ML/Gemini-Pro-Context-Option/m-p/684704/highlight/true#M4159
        # There is no direct way for 
        history = [{"role": "user", "parts": [{"text": f"System prompt: {main_prompt[0]['content']}"}],},
                   {"role": "model", "parts": [{"text": "Understood."}],},
                   {"role": "user", "parts": [{"text": f"{main_prompt[1]['content']}"}],}]
        #print(_GEMINI_DEFAULT_PARAMS)
        response = self.client.generate_content(history)
        response = response.text
        #print(response)
        return response
    
if __name__ == '__main__':
    gemini=GeminiModel('gemini-1.5-pro', None)
    system_prompt=""
    user_prompt=""
    gemini.predict([{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}])
