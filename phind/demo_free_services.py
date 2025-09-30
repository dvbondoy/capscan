#!/usr/bin/env python3
"""
Quick demo of free AI services
"""

from free_ai_services import PhindClient, IsouClient, PollinationsClient, SkyClient

def quick_demo():
    """Quick demo of free AI services"""
    print("🤖 Free AI Services Quick Demo")
    print("=" * 40)
    
    question = "What is Python programming?"
    
    # Test Phind (most reliable)
    print(f"\n1. Phind AI:")
    print("-" * 15)
    try:
        phind = PhindClient()
        response = phind.chat(question)
        print(f"✅ Success: {response[:100]}...")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Test Pollinations (fast and reliable)
    print(f"\n2. Pollinations AI:")
    print("-" * 20)
    try:
        poll = PollinationsClient()
        response = poll.chat(question)
        print(f"✅ Success: {response[:100]}...")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Test Sky (simple)
    print(f"\n3. Sky AI:")
    print("-" * 10)
    try:
        sky = SkyClient()
        response = sky.chat(question)
        print(f"✅ Success: {response[:100]}...")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Test Isou (with web search)
    print(f"\n4. Isou AI (with web search):")
    print("-" * 30)
    try:
        isou = IsouClient()
        response = isou.chat(question)
        print(f"✅ Success: {response[:100]}...")
    except Exception as e:
        print(f"❌ Error: {e}")

def interactive_demo():
    """Interactive demo"""
    print("\n🎯 Interactive Demo")
    print("=" * 20)
    
    # Use Phind as default (most reliable)
    client = PhindClient()
    
    print("Ask questions (type 'quit' to exit):")
    
    while True:
        try:
            question = input("\n❓ Your question: ").strip()
            
            if question.lower() in ['quit', 'exit', 'q']:
                print("👋 Goodbye!")
                break
            
            if not question:
                continue
            
            print("\n🤖 AI Response:")
            print("-" * 15)
            response = client.chat(question)
            print(f"\n{response}")
            
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--interactive":
        interactive_demo()
    else:
        quick_demo()
        
        # Ask if user wants interactive mode
        try:
            choice = input("\n🎮 Try interactive mode? (y/n): ").lower().strip()
            if choice in ['y', 'yes']:
                interactive_demo()
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
