#!/usr/bin/env python3
import argparse
import requests
import json
import time
import os
import readline
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By



def selenium_inject_test(base_url, param, payload, wait=3):
    options = Options()
    options.headless = True  # Run without opening a window

    driver = webdriver.Chrome(options=options)
    try:
        # Construct URL with payload
        full_url = f"{base_url}?{param}={payload}"
        print(f"[*] Loading URL: {full_url}")

        driver.get(full_url)
        time.sleep(wait)  # Wait for JS to load data, adjust if needed

        # Get full rendered HTML
        page_source = driver.page_source

        # Optionally, search for error indicators
        lowered = page_source.lower()
        error_signs = ["internal server error", "sql error", "database error", "exception", "warning", "stack trace"]

        if any(sign in lowered for sign in error_signs):
            print("[!] Possible error detected in page content.")
        else:
            print("[+] No obvious error detected.")

        # Print preview of rendered HTML or specific parts
        preview_length = 1000
        print(f"\n[Page Source Preview, first {preview_length} chars]:\n")
        print(page_source[:preview_length])

    finally:
        driver.quit()

def inject_payload(url, param, payload):
    """
    Send GET request with param in query string.
    """
    try:
        start_time = time.time()

        response = requests.get(url, params={param: payload})

        elapsed = time.time() - start_time

        result = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "target_url": url,
            "injected_param": param,
            "payload": payload,
            "method": "GET",
            "constructed_url": response.url,
            "status_code": response.status_code,
            "response_time": elapsed,
            "response_length": len(response.text),
            "response_body": response.text,

        }
        return result

    except Exception as e:
        print(f"[!] Request failed: {str(e)}")
        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "target_url": url,
            "injected_param": param,
            "payload": payload,
            "error": str(e)
        }
        
    except Exception as e:
        print(f"[!] Request failed: {str(e)}")
        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "target_url": url,
            "injected_param": param,
            "payload": payload,
            "error": str(e)
        }

def interactive_mode(urls, param,output_file):
    """
    Interactive loop for GET-only injection.
    """
    print("\n" + "=" * 50)
    print("GET Injection Interactive Console")
    print("=" * 50)
    print(f"[*] Loaded {len(urls)} target URLs")
    print(f"[*] Parameter: {param}")
    print(f"[*] Output File: {output_file}")
    print("\nType payloads to inject (type 'exit' to quit)")
    print("=" * 50 + "\n")

    while True:
        try:
            payload = input("payload> ").strip()
            if payload[:7].lower() == "--param":
                param = payload[8:].strip()
                print(f"[*] Parameter changed to: {param}")
                continue

            if payload.lower() in ["exit", "quit"]:
                print("[*] Exiting.")
                break

            if not payload:
                continue

            for url in urls:
                print(f"\n[*] Sending to: {url}")
                result = inject_payload(url, param, payload)

                print(f"\n[+] {result.get('method', 'N/A')} Request Sent")
                print(f"    Payload: {result.get('payload', '')}")
                if 'status_code' in result:
                    print(f"    Status: {result['status_code']}")
                    print(f"    Response Time: {result['response_time']:.2f}s")
                    print(f"    Response Length: {result['response_length']} bytes")
                if 'error' in result:
                    print(f"    Error: {result['error']}")
                print(f"    Constructed URL: {result.get('constructed_url', '')}")

                print("\n[Response Body Preview]")
                print(result.get('response_body', '[No response body]'))  # show first 500 chars
                print("-" * 50)

                if output_file:
                    with open(output_file, "a") as f:
                        f.write(json.dumps(result) + "\n")
                print("testing selenium injection...")
                selenium_inject_test(url, param, payload)

        except KeyboardInterrupt:
            print("\n[!] Exiting...")
            break
        except Exception as e:
            print(f"[!] Error: {str(e)}")

                    
        except KeyboardInterrupt:
            print("\n[!] Exiting...")
            break
        except Exception as e:
            print(f"[!] Error: {str(e)}")

def parse_cookies(cookie_str):
    """Parse cookies from string"""
    if not cookie_str:
        return None
    return {c.split('=')[0].strip(): c.split('=')[1].strip() for c in cookie_str.split(';')}

def main():
    parser = argparse.ArgumentParser(description="Interactive SQL Injection Tester")
    parser.add_argument("--url-file", "-f", required=True, 
                        help="File containing target URL (one per line)")
    parser.add_argument("--param", "-p", required=True, 
                        help="Parameter to inject")
    parser.add_argument("--output", "-o", required=True,
                        help="Output file for constructed requests (JSONL format)")
    
    args = parser.parse_args()
    
    # Read URLs from file
    try:
        with open(args.url_file, 'r') as f:
            urls = [line.strip() for line in f.readlines() if line.strip()]
    except Exception as e:
        print(f"[!] Error reading URL file: {str(e)}")
        return
    
    if not urls:
        print("[!] No valid URLs found in file")
        return
    
    # Parse cookies
    
    #cookies = parse_cookies(args.cookies) if args.cookies else None
    
    # Start interactive mode
    interactive_mode(
        urls=urls,
        param=args.param,
        output_file=args.output
    )

if __name__ == "__main__":
    main()