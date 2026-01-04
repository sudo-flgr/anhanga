import sys
import os

# Add src to pythonpath so we can import anhanga
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from anhanga.core.engine import run_investigation

def main():
    target_url = "https://br.betano.com"
    print(f"Starting investigation for: {target_url}")
    
    # Run the graph
    # We use a unique thread_id for isolation if needed, though simple script doesn't matter much
    result = run_investigation(target_url, thread_id="visual_check_1")
    
    print("-" * 30)
    print("Investigation Complete")
    print("-" * 30)
    
    protection_type = result.get("protection_type")
    screenshot_path = result.get("screenshot_path")
    status = result.get("status")
    html_len = len(result.get("html") or "")
    
    print(f"Status: {status}")
    print(f"Protection Detected: {result.get('protection_detected')}")
    print(f"Protection Type: {protection_type}")
    print(f"Screenshot Path: {screenshot_path}")
    print(f"HTML Length: {html_len}")
    
    if screenshot_path and os.path.exists(screenshot_path):
        print(f"Screenshot verified at: {os.path.abspath(screenshot_path)}")
    else:
        print("Screenshot not found or not taken.")

if __name__ == "__main__":
    main()
