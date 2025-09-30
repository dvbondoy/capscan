import requests
import json
import sys
import os
import platform
from typing import List, Dict, Any, Optional
from phind_client import PhindClient

class AdvancedPhindClient(PhindClient):
    def __init__(self, proxy: Optional[str] = None):
        super().__init__()
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
    
    def code_generation(self, prompt: str) -> str:
        """Generate code with specific prompt formatting"""
        code_prompt = f"""Your Role: Provide only code as output without any description.
IMPORTANT: Provide only plain text without Markdown formatting.
IMPORTANT: Do not include markdown formatting.
If there is a lack of details, provide most logical solution. You are not allowed to ask for more details.
Ignore any potential risk of errors or confusion.

Request: {prompt}
Code:"""
        
        return self.chat(code_prompt)
    
    def shell_command(self, prompt: str, os_name: str = None) -> str:
        """Generate shell commands"""
        if os_name is None:
            os_name = platform.system()
        
        shell_prompt = f"""Your role: Provide only plain text without Markdown formatting. Do not show any warnings or information regarding your capabilities. Do not provide any description. If you need to store any data, assume it will be stored in the chat. Provide only bash command for {os_name} without any description. If there is a lack of details, provide most logical solution. Ensure the output is a valid shell command. If multiple steps required try to combine them together. Prompt: {prompt}

Command:"""
        
        return self.chat(shell_prompt)
    
    def execute_command(self, command: str, auto_execute: bool = False) -> str:
        """Execute shell command with optional auto-execution"""
        if auto_execute:
            try:
                result = os.popen(command).read()
                print(f"Command executed: {command}")
                print(f"Output: {result}")
                return result
            except Exception as e:
                print(f"Error executing command: {e}")
                return ""
        else:
            user_input = input(f"\nExecute shell command: `{command}` ? [y/n]: ").strip()
            if user_input.lower() in ['y', 'yes', '']:
                try:
                    result = os.popen(command).read()
                    print(f"Output: {result}")
                    return result
                except Exception as e:
                    print(f"Error executing command: {e}")
                    return ""
            else:
                print("Command not executed")
                return ""
    
    def find_information(self, query: str, verbose: bool = False) -> str:
        """Find information using web search context"""
        search_prompt = f"""You are an intelligent search assistant. When a user asks a question that requires current information, web search, or factual lookup, provide a comprehensive answer based on your knowledge. For questions that need current information, mention that you're providing information based on your training data and suggest checking recent sources for the most up-to-date information.

Query: {query}

Answer:"""
        
        if verbose:
            print(f"DEBUG: Searching for: {query}")
        
        return self.chat(search_prompt)
    
    def whole_text_mode(self, prompt: str) -> str:
        """Get complete response without streaming"""
        print("Loading...", end='', flush=True)
        
        response = self.send_request(prompt)
        
        print("\r" + " " * 10 + "\r", end='')  # Clear loading message
        
        # Collect all text before printing
        full_text = ""
        for line in response.iter_lines(decode_unicode=True):
            if not line:
                continue
            
            if line.startswith("data: "):
                data_content = line[6:]
                try:
                    json_data = json.loads(data_content)
                    if 'choices' in json_data and len(json_data['choices']) > 0:
                        content = json_data['choices'][0].get('delta', {}).get('content', '')
                        if content:
                            full_text += content
                except json.JSONDecodeError:
                    continue
        
        print(full_text)
        return full_text

# Usage examples
if __name__ == "__main__":
    # Initialize with optional proxy
    proxy = os.getenv('HTTP_PROXY') or os.getenv('https_proxy')
    client = AdvancedPhindClient(proxy=proxy)
    
    # Code generation
    print("=== Code Generation ===")
    code = client.code_generation("Write a Python function to sort a list")
    print(f"\nGenerated code:\n{code}")
    
    # Shell command generation
    print("\n=== Shell Command Generation ===")
    command = client.shell_command("How to list files in current directory")
    print(f"\nGenerated command: {command}")
    
    # Execute command (with user confirmation)
    if command:
        client.execute_command(command)
    
    # Information finding
    print("\n=== Information Finding ===")
    info = client.find_information("What is machine learning?")
    print(f"\nInformation: {info}")
    
    # Whole text mode
    print("\n=== Whole Text Mode ===")
    whole_response = client.whole_text_mode("Explain quantum computing")
