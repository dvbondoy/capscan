import argparse
import sys
import os
import platform
import subprocess
import shlex
from phind_client import PhindClient
from phind_chat import PhindChat

def detect_shell_and_os():
    """Detect shell and operating system similar to Go implementation"""
    os_name = platform.system().lower()
    
    if os_name == "windows":
        # Check if PowerShell is available by checking PSModulePath environment variable
        if os.environ.get("PSModulePath"):
            return "powershell.exe", ["-Command"], "Windows"
        else:
            return "cmd.exe", ["/C"], "Windows"
    elif os_name == "darwin":
        shell = os.environ.get("SHELL", "/bin/bash")
        return shell, ["-c"], "MacOS"
    elif os_name == "linux":
        shell = os.environ.get("SHELL", "/bin/bash")
        return shell, ["-c"], "Linux"
    else:
        shell = os.environ.get("SHELL", "/bin/sh")
        return shell, ["-c"], os_name

def generate_shell_command(client, prompt, model):
    """Generate shell command using AI"""
    shell_name, _, os_name = detect_shell_and_os()
    
    # Create shell-specific prompt similar to Go implementation
    shell_prompt = f"""Your role: Provide only plain text without Markdown formatting. Do not show any warnings or information regarding your capabilities. Do not provide any description. If you need to store any data, assume it will be stored in the chat. Provide only {shell_name} command for {os_name} without any description. If there is a lack of details, provide most logical solution. Ensure the output is a valid shell command. If multiple steps required try to combine them together. Prompt: {prompt}

Command:"""
    
    print("Loading...", end='', flush=True)
    response = client.send_request(shell_prompt, model)
    print("\r" + " " * 10 + "\r", end='')  # Clear loading message
    
    return client.parse_streaming_response(response)

def execute_shell_command(command, auto_execute=False):
    """Execute shell command with optional confirmation"""
    shell_name, shell_options, os_name = detect_shell_and_os()
    
    # Clean the command (remove extra whitespace)
    command = command.strip()
    
    if not command:
        print("No command generated")
        return
    
    print(f"\nGenerated command: {command}")
    
    if not auto_execute:
        try:
            user_input = input("\nExecute shell command? [y/n]: ").strip()
            if user_input.lower() not in ['y', 'yes', '']:
                print("Command not executed")
                return
        except KeyboardInterrupt:
            print("\nCommand not executed")
            return
    
    try:
        # Execute the command
        if os_name == "Windows":
            # For Windows, use shell=True for proper command execution
            result = subprocess.run(
                command,
                shell=True,
                capture_output=False,  # Let output go to console
                text=True
            )
        else:
            # For Unix-like systems, use the detected shell
            cmd = [shell_name] + shell_options + [command]
            result = subprocess.run(
                cmd,
                capture_output=False,  # Let output go to console
                text=True
            )
        
        if result.returncode != 0:
            print(f"\nCommand failed with exit code: {result.returncode}")
            
    except Exception as e:
        print(f"\nError executing command: {e}")

def main():
    parser = argparse.ArgumentParser(description='Phind CLI Client')
    parser.add_argument('prompt', nargs='?', help='Your question or prompt')
    parser.add_argument('--model', default='Phind-70B', help='Model to use')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive mode')
    parser.add_argument('--system-prompt', help='System prompt')
    parser.add_argument('--shell', '-s', action='store_true', help='Generate and execute shell commands')
    parser.add_argument('--execute', '-y', action='store_true', help='Execute shell command without confirmation')
    
    args = parser.parse_args()
    
    client = PhindClient()
    
    if args.shell:
        if not args.prompt:
            print("Please provide a prompt for shell command generation")
            print("Example: python phind_cli.py --shell 'How to update system'")
            sys.exit(1)
        
        # Generate shell command
        command = generate_shell_command(client, args.prompt, args.model)
        
        # Execute the command
        execute_shell_command(command, auto_execute=args.execute)
        
    elif args.interactive:
        chat = PhindChat(model=args.model, system_prompt=args.system_prompt or "")
        chat.interactive_mode()
    elif args.prompt:
        response = client.chat(args.prompt, model=args.model)
        print(f"\n\nFull response: {response}")
    else:
        print("Please provide a prompt or use --interactive mode")
        sys.exit(1)

if __name__ == "__main__":
    main()
