#!/usr/bin/env python3
"""
AI Service Comparison - Compare different free AI services
"""

from free_ai_services import PhindClient, IsouClient, KimiClient, PollinationsClient, SkyClient
import time

class AIServiceComparison:
    """Compare different AI services"""
    
    def __init__(self):
        self.services = {
            'Phind': PhindClient(),
            'Isou': IsouClient(),
            'Kimi': KimiClient(),
            'Pollinations': PollinationsClient(),
            'Sky': SkyClient()
        }
    
    def test_service(self, service_name: str, question: str) -> dict:
        """Test a single service"""
        print(f"\n🔍 Testing {service_name}...")
        start_time = time.time()
        
        try:
            service = self.services[service_name]
            response = service.chat(question)
            end_time = time.time()
            
            return {
                'service': service_name,
                'success': True,
                'response_length': len(response),
                'response_preview': response[:200] + "..." if len(response) > 200 else response,
                'response_time': round(end_time - start_time, 2),
                'error': None
            }
        except Exception as e:
            end_time = time.time()
            return {
                'service': service_name,
                'success': False,
                'response_length': 0,
                'response_preview': "",
                'response_time': round(end_time - start_time, 2),
                'error': str(e)
            }
    
    def compare_services(self, question: str):
        """Compare all services with the same question"""
        print(f"🤖 AI Service Comparison")
        print(f"Question: {question}")
        print("=" * 60)
        
        results = []
        
        for service_name in self.services.keys():
            result = self.test_service(service_name, question)
            results.append(result)
            
            if result['success']:
                print(f"✅ {service_name}: {result['response_time']}s, {result['response_length']} chars")
            else:
                print(f"❌ {service_name}: Failed - {result['error']}")
        
        # Summary
        print(f"\n📊 Summary")
        print("-" * 30)
        successful = [r for r in results if r['success']]
        failed = [r for r in results if not r['success']]
        
        print(f"Successful: {len(successful)}/{len(results)}")
        print(f"Failed: {len(failed)}/{len(results)}")
        
        if successful:
            fastest = min(successful, key=lambda x: x['response_time'])
            longest_response = max(successful, key=lambda x: x['response_length'])
            
            print(f"\n🏆 Fastest: {fastest['service']} ({fastest['response_time']}s)")
            print(f"📝 Longest response: {longest_response['service']} ({longest_response['response_length']} chars)")
        
        return results
    
    def detailed_comparison(self, question: str):
        """Show detailed responses from all services"""
        print(f"\n🔍 Detailed Comparison")
        print(f"Question: {question}")
        print("=" * 80)
        
        for service_name, service in self.services.items():
            print(f"\n{'='*20} {service_name} {'='*20}")
            try:
                response = service.chat(question)
                print(response)
            except Exception as e:
                print(f"Error: {e}")
            print()

def main():
    """Run comparison tests"""
    comparison = AIServiceComparison()
    
    # Test questions
    questions = [
        "What is Python programming?",
        "Explain machine learning in simple terms",
        "Write a hello world program in Python"
    ]
    
    for question in questions:
        print(f"\n{'='*80}")
        print(f"Testing: {question}")
        print('='*80)
        
        # Quick comparison
        results = comparison.compare_services(question)
        
        # Ask if user wants detailed responses
        try:
            show_details = input(f"\nShow detailed responses for '{question}'? (y/n): ").lower().strip()
            if show_details in ['y', 'yes']:
                comparison.detailed_comparison(question)
        except KeyboardInterrupt:
            print("\nExiting...")
            break

if __name__ == "__main__":
    main()
