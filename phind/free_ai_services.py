#!/usr/bin/env python3
"""
Free AI Services - Python implementations of services that don't require API keys
Based on the Go tgpt implementation
"""

import requests
import json
import sys
import time
import random
import string
from typing import List, Dict, Any, Optional
from urllib.parse import quote

class BaseAIClient:
    """Base class for AI clients"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0'
        })
    
    def generate_random_id(self, length: int = 19) -> str:
        """Generate random ID for services that need it"""
        return ''.join(random.choices(string.digits, k=length))
    
    def parse_streaming_response(self, response: requests.Response) -> str:
        """Parse streaming response from various services"""
        full_text = ""
        
        for line in response.iter_lines(decode_unicode=True):
            if not line:
                continue
            
            # Handle different streaming formats
            if line.startswith("data: "):
                data_content = line[6:]
                try:
                    json_data = json.loads(data_content)
                    content = self.extract_content(json_data)
                    if content:
                        full_text += content
                        print(content, end='', flush=True)
                except json.JSONDecodeError:
                    continue
        
        return full_text
    
    def extract_content(self, json_data: Dict) -> str:
        """Extract content from JSON response - override in subclasses"""
        return ""

class PhindClient(BaseAIClient):
    """Phind AI client - completely free, no API key needed"""
    
    def __init__(self):
        super().__init__()
        self.base_url = "https://https.extension.phind.com/agent/"
        self.setup_headers()
    
    def setup_headers(self):
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': '*/*',
            'Accept-Encoding': 'Identity'
        })
    
    def chat(self, user_input: str, model: str = "Phind-70B", 
             system_prompt: str = "", prev_messages: List[Dict] = None) -> str:
        """Chat with Phind AI"""
        if prev_messages is None:
            prev_messages = []
        
        # Build message history
        message_history = []
        if system_prompt:
            message_history.append({
                "content": system_prompt,
                "role": "system"
            })
        message_history.extend(prev_messages)
        message_history.append({
            "content": user_input,
            "role": "user"
        })
        
        request_body = {
            "additional_extension_context": "",
            "allow_magic_buttons": True,
            "is_vscode_extension": True,
            "message_history": message_history,
            "requested_model": model,
            "user_input": user_input
        }
        
        try:
            response = self.session.post(
                self.base_url,
                json=request_body,
                stream=True,
                timeout=600
            )
            response.raise_for_status()
            return self.parse_streaming_response(response)
        except requests.exceptions.RequestException as e:
            print(f"Phind connection error: {e}")
            return ""
    
    def extract_content(self, json_data: Dict) -> str:
        """Extract content from Phind response"""
        if 'choices' in json_data and len(json_data['choices']) > 0:
            return json_data['choices'][0].get('delta', {}).get('content', '')
        return ""

class IsouClient(BaseAIClient):
    """Isou AI client - free with web search"""
    
    def __init__(self):
        super().__init__()
        self.base_url = "https://isou.chat/api/search"
        self.setup_headers()
    
    def setup_headers(self):
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Referer': 'https://isou.chat/search',
            'Origin': 'https://isou.chat'
        })
    
    def chat(self, user_input: str, model: str = "deepseek-ai/DeepSeek-R1-Distill-Qwen-32B") -> str:
        """Chat with Isou AI (includes web search)"""
        query = quote(user_input)
        url = f"{self.base_url}?q={query}"
        
        request_body = {
            "stream": True,
            "model": model,
            "provider": "siliconflow",
            "mode": "deep",
            "language": "all",
            "categories": ["science"],
            "engine": "SEARXNG",
            "locally": False,
            "reload": False
        }
        
        try:
            response = self.session.post(url, json=request_body, stream=True, timeout=600)
            response.raise_for_status()
            return self.parse_streaming_response(response)
        except requests.exceptions.RequestException as e:
            print(f"Isou connection error: {e}")
            return ""
    
    def extract_content(self, json_data: Dict) -> str:
        """Extract content from Isou response"""
        if 'data' in json_data:
            try:
                inner_data = json.loads(json_data['data'])
                if 'context' in inner_data and inner_data['context']:
                    # Show search context
                    ctx = inner_data['context']
                    return f"🔍 {ctx['id']}. {ctx['name']} - {ctx['url']}\n"
                elif 'reasoningContent' in inner_data and inner_data['reasoningContent']:
                    # Show reasoning
                    return f"💭 {inner_data['reasoningContent']}\n"
                elif 'content' in inner_data and inner_data['content']:
                    # Show main content
                    return inner_data['content']
            except (json.JSONDecodeError, KeyError):
                pass
        return ""

class KimiClient(BaseAIClient):
    """Kimi AI client - free with web search, limited context"""
    
    def __init__(self):
        super().__init__()
        self.base_url = "https://www.kimi.com/api/chat"
        self.device_id = self.generate_random_id(19)
        self.traffic_id = self.generate_random_id(19)
        self.access_token = ""
        self.chat_id = ""
        self.setup_headers()
    
    def setup_headers(self):
        self.session.headers.update({
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Content-Type': 'application/json',
            'Origin': 'https://www.kimi.com',
            'Priority': 'u=1, i',
            'X-Language': 'en-US',
            'X-Msh-Device-Id': self.device_id,
            'X-Msh-Platform': 'web',
            'X-Traffic-Id': self.traffic_id
        })
    
    def get_access_token(self) -> str:
        """Get access token from Kimi"""
        url = "https://www.kimi.com/api/device/register"
        
        try:
            response = self.session.post(url, json={})
            response.raise_for_status()
            data = response.json()
            return data.get('access_token', '')
        except requests.exceptions.RequestException as e:
            print(f"Kimi token error: {e}")
            return ""
    
    def get_chat_id(self, access_token: str) -> str:
        """Get chat ID from Kimi"""
        url = "https://www.kimi.com/api/chat"
        
        payload = {
            "name": "Unnamed Chat",
            "born_from": "home",
            "kimiplus_id": "kimi",
            "is_example": False,
            "source": "web",
            "tags": []
        }
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Cookie': f'kimi-auth={access_token}'
        }
        
        try:
            response = self.session.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            return data.get('id', '')
        except requests.exceptions.RequestException as e:
            print(f"Kimi chat ID error: {e}")
            return ""
    
    def chat(self, user_input: str, model: str = "k2") -> str:
        """Chat with Kimi AI"""
        if not self.access_token:
            self.access_token = self.get_access_token()
        if not self.chat_id:
            self.chat_id = self.get_chat_id(self.access_token)
        
        if not self.access_token or not self.chat_id:
            print("Failed to initialize Kimi client")
            return ""
        
        url = f"https://www.kimi.com/api/chat/{self.chat_id}/completion/stream"
        
        request_body = {
            "kimiplus_id": "kimi",
            "extend": {"sidebar": True},
            "model": model,
            "use_search": True,
            "messages": [{"role": "user", "content": user_input}],
            "refs": [],
            "history": [],
            "scene_labels": [],
            "use_semantic_memory": False,
            "use_deep_research": False
        }
        
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Cookie': f'kimi-auth={self.access_token}',
            'Referer': f'https://www.kimi.com/chat/{self.chat_id}'
        }
        
        try:
            response = self.session.post(url, json=request_body, headers=headers, stream=True, timeout=600)
            response.raise_for_status()
            return self.parse_streaming_response(response)
        except requests.exceptions.RequestException as e:
            print(f"Kimi connection error: {e}")
            return ""
    
    def extract_content(self, json_data: Dict) -> str:
        """Extract content from Kimi response"""
        if json_data.get('event') == 'cmpl':
            return json_data.get('text', '')
        return ""

class PollinationsClient(BaseAIClient):
    """Pollinations AI client - completely free"""
    
    def __init__(self):
        super().__init__()
        self.base_url = "https://text.pollinations.ai/openai"
        self.setup_headers()
    
    def setup_headers(self):
        self.session.headers.update({
            'Content-Type': 'application/json'
        })
    
    def chat(self, user_input: str, model: str = "openai", 
             system_prompt: str = "", prev_messages: List[Dict] = None) -> str:
        """Chat with Pollinations AI"""
        if prev_messages is None:
            prev_messages = []
        
        # Build messages
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.extend(prev_messages)
        messages.append({"role": "user", "content": user_input})
        
        request_body = {
            "model": model,
            "referrer": "tgpt",
            "stream": True,
            "messages": messages,
            "temperature": "1",
            "top_p": "1"
        }
        
        try:
            response = self.session.post(
                self.base_url,
                json=request_body,
                stream=True,
                timeout=600
            )
            response.raise_for_status()
            return self.parse_streaming_response(response)
        except requests.exceptions.RequestException as e:
            print(f"Pollinations connection error: {e}")
            return ""
    
    def extract_content(self, json_data: Dict) -> str:
        """Extract content from Pollinations response"""
        if 'choices' in json_data and len(json_data['choices']) > 0:
            return json_data['choices'][0].get('delta', {}).get('content', '')
        return ""

class SkyClient(BaseAIClient):
    """Sky AI client - free"""
    
    def __init__(self):
        super().__init__()
        self.base_url = "https://api.sky.foresko.com/v1/create-chat-completion"
        self.setup_headers()
    
    def setup_headers(self):
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept-Charset': 'UTF-8',
            'Accept-Encoding': 'gzip',
            'Connection': 'Keep-Alive',
            'User-Agent': 'ktor-client'
        })
    
    def chat(self, user_input: str, system_prompt: str = "", 
             prev_messages: List[Dict] = None) -> str:
        """Chat with Sky AI"""
        if prev_messages is None:
            prev_messages = []
        
        # Build messages
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.extend(prev_messages)
        messages.append({"role": "user", "content": user_input})
        
        request_body = {"messages": messages}
        
        try:
            response = self.session.post(
                self.base_url,
                json=request_body,
                stream=True,
                timeout=600
            )
            response.raise_for_status()
            return self.parse_streaming_response(response)
        except requests.exceptions.RequestException as e:
            print(f"Sky connection error: {e}")
            return ""
    
    def extract_content(self, json_data: Dict) -> str:
        """Extract content from Sky response"""
        if 'choices' in json_data and len(json_data['choices']) > 0:
            return json_data['choices'][0].get('delta', {}).get('content', '')
        return ""

# Usage examples
def main():
    """Demo all free AI services"""
    print("🤖 Free AI Services Demo")
    print("=" * 50)
    
    question = "What is machine learning?"
    
    # Test Phind
    print("\n1. Phind AI (Default)")
    print("-" * 20)
    phind = PhindClient()
    response = phind.chat(question)
    print(f"\nPhind response: {response[:100]}...")
    
    # Test Isou
    print("\n2. Isou AI (With Web Search)")
    print("-" * 30)
    isou = IsouClient()
    response = isou.chat(question)
    print(f"\nIsou response: {response[:100]}...")
    
    # Test Pollinations
    print("\n3. Pollinations AI")
    print("-" * 20)
    poll = PollinationsClient()
    response = poll.chat(question)
    print(f"\nPollinations response: {response[:100]}...")
    
    # Test Sky
    print("\n4. Sky AI")
    print("-" * 10)
    sky = SkyClient()
    response = sky.chat(question)
    print(f"\nSky response: {response[:100]}...")
    
    # Test Kimi (may take longer due to auth)
    print("\n5. Kimi AI (With Web Search)")
    print("-" * 30)
    kimi = KimiClient()
    response = kimi.chat(question)
    print(f"\nKimi response: {response[:100]}...")

if __name__ == "__main__":
    main()
