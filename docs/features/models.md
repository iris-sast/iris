## Supported Models
We support the following models with our models API wrapper (found in `src/models`) in the project. Listed below are the arguments you can use for `--llm` when using `src/iris.py`. You're free to use your own way of instantiating models or adding on to the existing library. Some of them require your own API key or license agreement on HuggingFace. 

<details>
  <summary>List of Models</summary>
  
### Codegen
- `codegen-16b-multi`
- `codegen25-7b-instruct`
- `codegen25-7b-multi`

### Codellama
#### Standard Models
- `codellama-70b-instruct`
- `codellama-34b`
- `codellama-34b-python`
- `codellama-34b-instruct`
- `codellama-13b-instruct`
- `codellama-7b-instruct`

### CodeT5p
- `codet5p-16b-instruct`
- `codet5p-16b`
- `codet5p-6b`
- `codet5p-2b`

### DeepSeek
- `deepseekcoder-33b`
- `deepseekcoder-7b`
- `deepseekcoder-v2-15b`

### Gemini
- All Gemini models are supported, including those below, other model names can be found in the Gemini API documentation. 
- `gemini-1.5-pro`
- `gemini-1.5-flash`
- `gemini-pro`
- `gemini-pro-vision`
- `gemini-1.0-pro-vision`

### Gemma
- `gemma-7b`
- `gemma-7b-it`
- `gemma-2b`
- `gemma-2b-it`
- `codegemma-7b-it`
- `gemma-2-27b`
- `gemma-2-9b`

### GPT
- `gpt-4`
- `gpt-3.5`
- `gpt-4-1106`
- `gpt-4-0613`

### LLaMA
#### LLaMA-2
- `llama-2-7b-chat`
- `llama-2-13b-chat`
- `llama-2-70b-chat`
- `llama-2-7b`
- `llama-2-13b`
- `llama-2-70b`

#### LLaMA-3
- `llama-3-8b`
- `llama-3.1-8b`
- `llama-3-70b`
- `llama-3.1-70b`
- `llama-3-70b-tai`

### Mistral
- `mistral-7b-instruct`
- `mixtral-8x7b-instruct`
- `mixtral-8x7b`
- `mixtral-8x22b`
- `mistral-codestral-22b`

### Qwen
- `qwen2.5-coder-7b`
- `qwen2.5-coder-1.5b`
- `qwen2.5-14b`
- `qwen2.5-32b`
- `qwen2.5-72b`

### StarCoder
- `starcoder`
- `starcoder2-15b`

### WizardLM
#### WizardCoder
- `wizardcoder-15b`
- `wizardcoder-34b-python`
- `wizardcoder-13b-python`

#### WizardLM Base
- `wizardlm-70b`
- `wizardlm-13b`
- `wizardlm-30b`

### Ollama

You need to install the `ollama` package manually.

- `qwen2.5-coder:latest`
- `qwen2.5:32b`
- `llama3.2:latest`
- `deepseek-r1:32b`
- `deepseek-r1:latest`

</details>
