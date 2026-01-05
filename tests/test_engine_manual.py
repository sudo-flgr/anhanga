import asyncio
import sys
import os

# Ensure src is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from anhanga.core.engine import run_investigation_async

async def main():
    print("--- Testing Standard Scraper Path (Localhost/No Protection) ---")
    # We expect this to go InfraHunter -> StandardScraper
    # Note: If no server is running at example.com, it might error in InfraHunter but that's handled.
    try:
        result = await run_investigation_async("https://example.com", thread_id="test_1")
        print("\n[Result Summary]")
        print(f"URL: {result['url']}")
        print(f"Protection: {result['protection_type']}")
        print(f"Status: {result['status']}")
        print(f"Scraper Used: {'Stealth' if 'Camoufox' in str(result.get('errors')) or result.get('screenshot_path') else 'Standard'}") # Rough check
        print(f"Screenshot: {result.get('screenshot_path')}")
    except Exception as e:
        print(f"Execution Error: {e}")

    print("\n--- Testing Standard Scraper Path (python.org) ---")
    try:
        result = await run_investigation_async("https://www.python.org", thread_id="test_2")
        print("\n[Result Summary]")
        print(f"URL: {result['url']}")
        print(f"Protection: {result['protection_type']}")
        print(f"Status: {result['status']}")
        print(f"Scraper Used: {'Stealth' if 'Camoufox' in str(result.get('errors')) or result.get('screenshot_path') else 'Standard'}")
        print(f"Screenshot: {result.get('screenshot_path')}")
    except Exception as e:
        print(f"Execution Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
