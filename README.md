# OpenSOC-AI

OpenSOC-AI is a lightweight, open-source security log analysis framework designed to automate the detection and classification of real-world cyber threats using a fine-tuned Large Language Model (LLM). Built for efficiency, it runs entirely locally on consumer hardware, removing the need for costly API dependencies.

## Key Capabilities

- **Threat Classification:** Automatically classifies potential threats directly from raw logs.
- **MITRE ATT&CK Mapping:** Aligns detected attacks to standard MITRE ATT&CK techniques.
- **Severity & Risk Scoring:** Assigns actionable severity and risk scores to incidents.
- **Remediation Generation:** Provides actionable remediation recommendations based on the detected threats.

## Architecture & Models

The framework leverages a fine-tuned **TinyLlama-1.1B** model utilizing LoRA (QLoRA) parameter-efficient tuning techniques to ensure rapid inference times without sacrificing analytical capability. 

## Quick Start Guide

### Prerequisites

Ensure you have the required dependencies installed (e.g., PyTorch, Transformers, PEFT).

```bash
pip install -r requirements.txt
```

### Inference Example

You can easily instantiate the model and adapter for log analysis using the following script:

```python
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel

# Define base model and adapter
base_model = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
adapter_path = "ShauryaSingh/opensoc-ai"

# Load tokenizer and model
tokenizer = AutoTokenizer.from_pretrained(base_model)
model = AutoModelForCausalLM.from_pretrained(base_model)

# Load PEFT adapter
model = PeftModel.from_pretrained(model, adapter_path)

# Sample log input
input_text = "Failed login attempts detected from multiple IPs"

# Tokenize and generate response
inputs = tokenizer(input_text, return_tensors="pt")
outputs = model.generate(**inputs, max_new_tokens=200)

print(tokenizer.decode(outputs[0]))
```

## Citation

If you utilize this framework in your research, please cite the following:

```bibtex
@article{singh2026opensocai,
  title={OpenSOC-AI: Democratizing Security Operations with Parameter Efficient LLM Log Analysis},
  author={Singh, Shaurya},
  year={2026}
}
```

## License

This project is distributed under the MIT License.
