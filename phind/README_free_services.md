# Free AI Services - No API Key Required

This directory contains Python implementations of various free AI services that don't require API keys, based on the Go tgpt implementation.

## 🆓 Available Free Services

### 1. **Phind** (Recommended)
- **Status**: ✅ Completely free, no API key needed
- **Model**: Phind-70B
- **Features**: Excellent for developers, coding questions
- **Speed**: Fast
- **Reliability**: High
- **Use Case**: Programming, technical questions

### 2. **Isou** 
- **Status**: ✅ Free with web search
- **Model**: DeepSeek-R1-Distill-Qwen-32B
- **Features**: Web search integration, science-focused
- **Speed**: Medium
- **Reliability**: High
- **Use Case**: Research, current information, science topics

### 3. **Kimi**
- **Status**: ✅ Free with web search, limited context
- **Model**: k2, k1.5
- **Features**: Web search, semantic memory
- **Speed**: Medium (requires auth setup)
- **Reliability**: Medium
- **Use Case**: General questions with web search

### 4. **Pollinations**
- **Status**: ✅ Completely free
- **Model**: gpt-4o (default), many models available
- **Features**: Text generation, image generation
- **Speed**: Fast
- **Reliability**: High
- **Use Case**: General purpose, creative writing

### 5. **Sky**
- **Status**: ✅ Free
- **Model**: gpt-4.1-mini
- **Features**: Simple chat completion
- **Speed**: Fast
- **Reliability**: Medium
- **Use Case**: Quick responses, simple questions

## 📁 Files

- `free_ai_services.py` - All free AI service implementations
- `service_comparison.py` - Compare different services
- `phind_client.py` - Dedicated Phind client (original)
- `phind_chat.py` - Phind with conversation memory
- `advanced_phind_client.py` - Advanced Phind features

## 🚀 Quick Start

```bash
# Install dependencies
pip install requests

# Test all free services
python free_ai_services.py

# Compare services
python service_comparison.py

# Use specific service
python -c "
from free_ai_services import PhindClient
client = PhindClient()
print(client.chat('What is Python?'))
"
```

## 📊 Service Comparison

| Service | Free | API Key | Web Search | Speed | Best For |
|---------|------|---------|------------|-------|----------|
| Phind | ✅ | ❌ | ❌ | Fast | Programming |
| Isou | ✅ | ❌ | ✅ | Medium | Research |
| Kimi | ✅ | ❌ | ✅ | Medium | General + Search |
| Pollinations | ✅ | ❌ | ❌ | Fast | General |
| Sky | ✅ | ❌ | ❌ | Fast | Quick answers |

## 🎯 Usage Examples

### Basic Usage
```python
from free_ai_services import PhindClient, IsouClient, PollinationsClient

# Phind - Great for coding
phind = PhindClient()
code_response = phind.chat("Write a Python function to sort a list")

# Isou - Great for research
isou = IsouClient()
research_response = isou.chat("Latest developments in AI")

# Pollinations - General purpose
poll = PollinationsClient()
general_response = poll.chat("Explain quantum computing")
```

### Service Comparison
```python
from service_comparison import AIServiceComparison

comparison = AIServiceComparison()
results = comparison.compare_services("What is machine learning?")
```

### Advanced Features
```python
# With conversation memory
from phind_chat import PhindChat

chat = PhindChat(system_prompt="You are a helpful coding assistant.")
response1 = chat.chat("What is Python?")
response2 = chat.chat("Can you give me an example?")  # Remembers context
```

## 🔧 Configuration

### Environment Variables
```bash
# Optional proxy settings
export HTTP_PROXY=http://proxy:port
export https_proxy=http://proxy:port

# Optional TLS client profile (for advanced users)
export TLS_CLIENT_PROFILE=firefox_117
```

### Custom Headers
```python
# Customize headers if needed
client = PhindClient()
client.session.headers.update({
    'Custom-Header': 'value'
})
```

## ⚠️ Important Notes

### Rate Limits
- **Phind**: No known limits, but be respectful
- **Isou**: Unknown limits, moderate usage recommended
- **Kimi**: May have rate limits, uses device registration
- **Pollinations**: Community service, please be respectful
- **Sky**: Unknown limits, moderate usage recommended

### Legal Considerations
- These services are free but may have terms of service
- Respect rate limits and usage guidelines
- Some services may require attribution
- Check individual service terms before commercial use

### Reliability
- **Most Reliable**: Phind, Pollinations
- **Moderate**: Isou, Sky
- **Variable**: Kimi (due to auth complexity)

## 🐛 Troubleshooting

### Common Issues

1. **Connection Errors**
   ```python
   # Check internet connection
   import requests
   response = requests.get("https://httpbin.org/get")
   print("Internet:", response.status_code == 200)
   ```

2. **Service Unavailable**
   ```python
   # Try different service
   from free_ai_services import PollinationsClient
   client = PollinationsClient()
   response = client.chat("Hello")
   ```

3. **Slow Responses**
   ```python
   # Use faster services
   from free_ai_services import SkyClient
   client = SkyClient()  # Usually faster
   ```

### Debug Mode
```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Enable requests debugging
import requests
import urllib3
urllib3.disable_warnings()
```

## 🔄 Migration from Go Version

If you're migrating from the Go tgpt version:

```bash
# Go version
tgpt --provider phind "What is Python?"

# Python version
python -c "
from free_ai_services import PhindClient
client = PhindClient()
print(client.chat('What is Python?'))
"
```

## 📈 Performance Tips

1. **Use Phind for coding questions** - Best performance and accuracy
2. **Use Isou for research** - Includes web search
3. **Use Pollinations for general questions** - Good balance
4. **Use Sky for quick answers** - Fastest response
5. **Cache responses** - Store frequently asked questions

## 🤝 Contributing

Feel free to:
- Add new free services
- Improve existing implementations
- Add better error handling
- Optimize performance
- Add more features

## 📄 License

Same as the original Go tgpt project - GPL-3.0
