#!/usr/bin/env python3
"""
Example usage of the Phind Python client
This file demonstrates various ways to use the Phind client
"""

from phind_client import PhindClient
from phind_chat import PhindChat
from advanced_phind_client import AdvancedPhindClient
import os

def basic_example():
    """Basic usage example"""
    print("=== Basic Usage Example ===")
    client = PhindClient()
    
    # Simple question
    response = client.chat("What is Python programming?")
    print(f"\nResponse: {response}")

def interactive_example():
    """Interactive chat example"""
    print("\n=== Interactive Chat Example ===")
    chat = PhindChat(
        system_prompt="You are a helpful AI assistant specialized in programming.",
        model="Phind-70B"
    )
    
    # Simulate a conversation
    questions = [
        "Hello! Can you help me with Python?",
        "What's the difference between a list and a tuple?",
        "Can you show me how to create a class?"
    ]
    
    for question in questions:
        print(f"\n--- Question: {question} ---")
        response = chat.chat(question)
        print(f"Response: {response}")

def code_generation_example():
    """Code generation example"""
    print("\n=== Code Generation Example ===")
    client = AdvancedPhindClient()
    
    # Generate code
    code_prompt = "Write a Python function to calculate fibonacci numbers"
    code = client.code_generation(code_prompt)
    print(f"Generated code:\n{code}")

def shell_command_example():
    """Shell command generation example"""
    print("\n=== Shell Command Example ===")
    client = AdvancedPhindClient()
    
    # Generate shell command
    command_prompt = "How to find all Python files in the current directory"
    command = client.shell_command(command_prompt)
    print(f"Generated command: {command}")
    
    # Ask user if they want to execute it
    if command:
        print(f"\nWould you like to execute: {command}")
        # Uncomment the next line to actually execute (be careful!)
        # client.execute_command(command)

def information_finding_example():
    """Information finding example"""
    print("\n=== Information Finding Example ===")
    client = AdvancedPhindClient()
    
    # Find information
    query = "What is machine learning and how does it work?"
    info = client.find_information(query, verbose=True)
    print(f"Information: {info}")

def conversation_memory_example():
    """Demonstrate conversation memory"""
    print("\n=== Conversation Memory Example ===")
    chat = PhindChat(system_prompt="You are a helpful assistant.")
    
    # First question
    print("Q1: What is a variable in programming?")
    response1 = chat.chat("What is a variable in programming?")
    print(f"A1: {response1}")
    
    # Follow-up question that relies on previous context
    print("\nQ2: Can you give me an example?")
    response2 = chat.chat("Can you give me an example?")
    print(f"A2: {response2}")
    
    # Another follow-up
    print("\nQ3: What about in Python specifically?")
    response3 = chat.chat("What about in Python specifically?")
    print(f"A3: {response3}")

def different_models_example():
    """Example with different models"""
    print("\n=== Different Models Example ===")
    client = PhindClient()
    
    # Try different models (if available)
    models = ["Phind-70B"]  # Add other models as they become available
    
    for model in models:
        print(f"\n--- Using model: {model} ---")
        response = client.chat(
            "Explain recursion in programming",
            model=model
        )
        print(f"Response: {response}")

def error_handling_example():
    """Demonstrate error handling"""
    print("\n=== Error Handling Example ===")
    client = PhindClient()
    
    try:
        # This should work normally
        response = client.chat("Hello, how are you?")
        print(f"Normal response: {response}")
    except Exception as e:
        print(f"Error occurred: {e}")

def proxy_example():
    """Example with proxy configuration"""
    print("\n=== Proxy Configuration Example ===")
    
    # Check if proxy is configured
    proxy = os.getenv('HTTP_PROXY') or os.getenv('https_proxy')
    if proxy:
        print(f"Using proxy: {proxy}")
        client = AdvancedPhindClient(proxy=proxy)
    else:
        print("No proxy configured, using direct connection")
        client = AdvancedPhindClient()
    
    response = client.chat("What is the weather like?")
    print(f"Response: {response}")

def main():
    """Run all examples"""
    print("Phind Python Client - Usage Examples")
    print("=" * 50)
    
    try:
        # Run examples
        basic_example()
        interactive_example()
        code_generation_example()
        shell_command_example()
        information_finding_example()
        conversation_memory_example()
        different_models_example()
        error_handling_example()
        proxy_example()
        
        print("\n" + "=" * 50)
        print("All examples completed successfully!")
        
    except KeyboardInterrupt:
        print("\n\nExamples interrupted by user")
    except Exception as e:
        print(f"\nError running examples: {e}")

if __name__ == "__main__":
    main()
