import requests
import json

class Nvidia:
    def __init__(self,apikey,system_prompt):
        
        self.model = "nvidia/nemotron-nano-9b-v2:free"
        self.base_url = "https://openrouter.ai/api/v1/chat/completions"
        self.api_key = apikey
        self.prompt=None
        self.system_prompt=system_prompt

    def chat(self, prompt: str) -> str:
        self.prompt=prompt
        if not self.api_key:
            raise ValueError("You must call configure() first.")

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": f"{self.system_prompt} \n {self.prompt}"}]
        }

        r = requests.post(self.base_url, headers=headers, data=json.dumps(payload))

        if r.status_code != 200:
            raise Exception(f"OpenRouter API Error {r.status_code}: {r.text}")

        return r.json()["choices"][0]["message"]["content"]
