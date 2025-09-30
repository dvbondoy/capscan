import requests
import json
import sys
from typing import List, Dict, Any, Optional

class PhindClient:
    def __init__(self):
        self.base_url = "https://https.extension.phind.com/agent/"
        self.session = requests.Session()
        self.setup_headers()
    
    def setup_headers(self):
        """Set up the same headers as the Go implementation"""
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': '',
            'Accept': '*/*',
            'Accept-Encoding': 'Identity'
        })
    
    def create_request_body(self, user_input: str, model: str = "Phind-70B", 
                          system_prompt: str = "", prev_messages: List[Dict] = None) -> Dict:
        """Create the request body matching the Go struct"""
        if prev_messages is None:
            prev_messages = []
        
        # Add system prompt as first message if provided
        message_history = []
        if system_prompt:
            message_history.append({
                "content": system_prompt,
                "role": "system"
            })
        
        # Add previous messages
        message_history.extend(prev_messages)
        
        # Add current user input
        message_history.append({
            "content": user_input,
            "role": "user"
        })
        
        return {
            "additional_extension_context": "",
            "allow_magic_buttons": True,
            "is_vscode_extension": True,
            "message_history": message_history,
            "requested_model": model,
            "user_input": user_input
        }
    
    def send_request(self, user_input: str, model: str = "Phind-70B", 
                    system_prompt: str = "", prev_messages: List[Dict] = None) -> requests.Response:
        """Send request to Phind API"""
        request_body = self.create_request_body(user_input, model, system_prompt, prev_messages)
        
        try:
            response = self.session.post(
                self.base_url,
                json=request_body,
                stream=True,  # Important for streaming responses
                timeout=600
            )
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            print(f"Connection error: {e}")
            sys.exit(1)
    
    def parse_streaming_response(self, response: requests.Response) -> str:
        """Parse streaming response similar to GetMainText in Go"""
        full_text = ""
        
        for line in response.iter_lines(decode_unicode=True):
            if not line:
                continue
            
            # Look for "data: " prefix (Server-Sent Events format)
            if line.startswith("data: "):
                data_content = line[6:]  # Remove "data: " prefix
                
                try:
                    # Parse JSON response
                    json_data = json.loads(data_content)
                    
                    # Extract content from the response structure
                    if 'choices' in json_data and len(json_data['choices']) > 0:
                        content = json_data['choices'][0].get('delta', {}).get('content', '')
                        if content:
                            full_text += content
                            print(content, end='', flush=True)  # Stream output
                
                except json.JSONDecodeError:
                    # Skip malformed JSON
                    continue
        
        return full_text
    
    def chat(self, user_input: str, model: str = "Phind-70B", 
             system_prompt: str = "", prev_messages: List[Dict] = None) -> str:
        """Main chat function"""
        print("Loading...", end='', flush=True)
        
        response = self.send_request(user_input, model, system_prompt, prev_messages)
        
        print("\r" + " " * 10 + "\r", end='')  # Clear loading message
        
        return self.parse_streaming_response(response)

# Usage example
if __name__ == "__main__":
    client = PhindClient()
    
    # Simple usage
    response = client.chat("What is Python programming?")
    print(f"\n\nFull response: {response}")
