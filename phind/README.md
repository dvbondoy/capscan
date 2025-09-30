# Phind Python Client

A Python implementation that replicates the functionality of the Go-based tgpt application for connecting to Phind's AI service.

## Features

- **No API Key Required**: Just like the original Go version, this doesn't require any authentication
- **Streaming Responses**: Real-time response display as the AI generates text
- **Conversation Memory**: Maintains context across interactions
- **Multiple Modes**: Interactive chat, code generation, shell commands, and more
- **Shell Command Generation**: Generate and execute shell commands with AI assistance
- **Cross-platform**: Works on Windows, macOS, and Linux
- **Auto-execution**: Optional auto-execution of generated shell commands

## Installation

1. Install Python 3.7 or higher
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Files Overview

- `phind_client.py` - Basic Phind client with core functionality
- `phind_chat.py` - Enhanced client with conversation memory and interactive mode
- `phind_cli.py` - Command-line interface
- `advanced_phind_client.py` - Advanced features like code generation and shell commands
- `requirements.txt` - Python dependencies

## Usage Examples

### Basic Usage

```python
from phind_client import PhindClient

client = PhindClient()
response = client.chat("What is Python programming?")
print(response)
```

### Interactive Mode

```python
from phind_chat import PhindChat

chat = PhindChat(system_prompt="You are a helpful AI assistant.")
chat.interactive_mode()
```

### Command Line Interface

```bash
# Basic usage
python phind_cli.py "What is machine learning?"

# Interactive mode
python phind_cli.py --interactive

# With custom model
python phind_cli.py --model "Phind-70B" "Explain quantum computing"

# With system prompt
python phind_cli.py --system-prompt "You are a coding expert" "Write a Python function"

# Shell command generation and execution
python phind_cli.py --shell "How to update my system"
python phind_cli.py --shell "list files in current directory"
python phind_cli.py --shell --execute "create a backup of important files"

# Auto-execute shell commands without confirmation
python phind_cli.py --shell --execute "show system information"
```

### Shell Command Feature

The shell command feature allows you to generate and execute shell commands using AI assistance. This is similar to the `--shell` flag in the original tgpt Go application.

#### How it works:

1. **Command Generation**: The AI analyzes your request and generates an appropriate shell command
2. **Platform Detection**: Automatically detects your operating system and shell (PowerShell, CMD, Bash, etc.)
3. **Confirmation**: Asks for confirmation before executing (unless `--execute` flag is used)
4. **Execution**: Runs the command in your system's shell

#### Examples:

```bash
# Generate a command to list files
python phind_cli.py --shell "show me all Python files in this directory"

# Generate and auto-execute a command
python phind_cli.py --shell --execute "create a backup of my documents"

# System maintenance commands
python phind_cli.py --shell "check disk space usage"
python phind_cli.py --shell "update all packages"

# File operations
python phind_cli.py --shell "find all large files over 100MB"
python phind_cli.py --shell "compress all log files"
```

#### Safety Features:

- **Confirmation Prompt**: By default, asks for confirmation before executing
- **Command Display**: Shows the generated command before execution
- **Error Handling**: Displays error messages if command execution fails
- **Platform Awareness**: Generates commands appropriate for your operating system

### Advanced Features

```python
from advanced_phind_client import AdvancedPhindClient

client = AdvancedPhindClient()

# Code generation
code = client.code_generation("Write a Python function to sort a list")

# Shell command generation
command = client.shell_command("How to update my system")

# Information finding
info = client.find_information("What is the latest news about AI?")

# Execute commands
client.execute_command(command, auto_execute=False)
```

## How It Works

The Python client replicates the exact same HTTP request structure as the Go version:

1. **Request Format**: Sends POST requests to `https://https.extension.phind.com/agent/`
2. **Headers**: Uses the same headers as the Go implementation
3. **Request Body**: Matches the exact JSON structure expected by Phind
4. **Response Processing**: Handles Server-Sent Events (SSE) streaming format
5. **No Authentication**: Works without API keys, just like the original

## Request Structure

The client sends requests with this structure:

```json
{
    "additional_extension_context": "",
    "allow_magic_buttons": true,
    "is_vscode_extension": true,
    "message_history": [
        {
            "content": "system prompt",
            "role": "system"
        },
        {
            "content": "user input",
            "role": "user"
        }
    ],
    "requested_model": "Phind-70B",
    "user_input": "user input"
}
```

## Response Processing

The client processes streaming responses by:
1. Looking for lines starting with "data: "
2. Parsing JSON content from each data line
3. Extracting content from the `choices[0].delta.content` field
4. Streaming the output in real-time

## Error Handling

- **Connection Errors**: Displays helpful error messages
- **HTTP Errors**: Shows status codes and response details
- **JSON Parsing**: Gracefully handles malformed responses
- **Timeout**: 600-second timeout for requests

## Legal Considerations

- This client replicates the functionality of the original Go application
- No API keys are used - it relies on Phind's public endpoints
- Please ensure compliance with Phind's terms of service
- Be respectful with rate limits and usage

## Differences from Go Version

1. **HTTP Library**: Uses `requests` instead of `tls_client`
2. **JSON Handling**: Uses Python's `json` module
3. **Streaming**: Uses `response.iter_lines()` for streaming
4. **Error Handling**: Python exception handling
5. **Memory Management**: Python's garbage collection

## Troubleshooting

- **Connection Issues**: Check your internet connection
- **Import Errors**: Ensure all dependencies are installed
- **Rate Limiting**: If you get rate limited, wait before making more requests
- **Proxy Issues**: Set HTTP_PROXY or https_proxy environment variables if needed

## Contributing

Feel free to submit issues and enhancement requests!
