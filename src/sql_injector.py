#!/usr/bin/env python3
import argparse
import requests
import json
import time
import pathlib
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


def check_url(url):
    """
    Check if the URL is valid.
    """
    try:
        parsed = urlparse(url)
        if not all([parsed.scheme, parsed.netloc]):
            raise ValueError("Invalid URL")
        return True
    except Exception as e:
        return False

def inject_payload(url, param, payload):
    """
    Send GET request with param in query string.
    """
    try:
        start_time = time.time()

        response = requests.get(url, param + payload)
        print(response.url)

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

def interactive_mode(urls, param,output_file, injection_type, cookie_string=None):
    """
    SQL Injection tool.
    """
    print("\n" + "=" * 80 )
    print("SQL Injection Interactive Console")
    print("=" * 80)
    print(f"[*] Loaded {len(urls)} target URLs")
    print(f"[*] URL to inject: {urls[0]}")
    print(f"[*] injection type: {injection_type}")
    print(f"[*] Parameter: {param}")
    print(f"[*] Output File: {output_file}")
    print(f"[*] Current Cookie: {cookie_string if cookie_string else 'None'}")

    print("=" * 80 + "\n")
    print("Options:")
    print(f"--param <text>\t\t Change parameter to inject (default: {param})")
    print(f"--type <1|2|3>\t\t Chnage injection type (1: GET, 2: POST, 3: Blind)")
    print(f"--cookie <cookie>\t Set cookie string")
    print(f"--add-url <url>\t\t Add new URL")
    print(f"--delete-url <index>\t Delete URL at index")
    print(f"--list-urls\t\t List all target URLs")
    print(f"--change-url <index>\t Switch current URL ")
    print(f"--payload <payload>\t Set payload")
    print(f"--display\t\t Display current url & payload")
    print(f"--run \t\t\t Run the current payload ")
    print(f"  exit\t\t\t Exit the tool")
    print("=" * 80 + "\n")

    pending_payload = None

    while True:
        try:
            cmd = input("cmd> ").strip().lower()

            if cmd in ("exit", "quit"):
                print("[*] Exiting.")
                break   
            
            elif cmd.startswith("--add-url "):
                new_url = cmd[10:].strip()
                if check_url(new_url):
                    path_to_urls = pathlib.Path().resolve() / "targets" / "urls.txt"
                    with open(f"{path_to_urls}", "a+") as f:
                        f.write(new_url + "\n")
                    urls.append(new_url)
                    print(f"[*] Added new URL: {new_url}")
                    f.close()
                else:
                    print("[!] Invalid URL. Please provide a valid URL.")

            elif cmd.startswith("--delete-url "):
                try:
                    index = int(cmd[13:]) - 1
                    if 0 <= index < len(urls):
                        deleted_url = urls.pop(index)
                        print(f"[*] Deleted URL: {deleted_url}")
                        # Update the file
                        path_to_urls = pathlib.Path().resolve() / "targets" / "urls.txt"
                        with open(f"{path_to_urls}", "w") as f:
                            f.writelines("\n".join(urls) + "\n")
                        f.close()
                    else:
                        print("[!] Invalid index. Please provide a valid index.")
                except ValueError:
                    print("[!] Invalid input. Please provide a number.")
                
            elif cmd == "--list-urls":
                print("\n[*] Current URLs:")
                for i, url in enumerate(urls):
                    print(f"{i + 1}: {url}")
                print("=" * 80) 

            elif cmd.startswith("--display"):
                print(f"\n[*] Current URL: {urls[0]}")
                print(f"[*] Current Payload: {pending_payload if pending_payload else 'None'}")
                print(f"[*] Current Parameter: {param}")
                print(f"[*] Current Injection Type: {injection_type}")
                print(f"[*] Current Cookie: {cookie_string if cookie_string else 'None'}")
                print(f"[*] Constructed URL: {urls[0]}?{param}={pending_payload if pending_payload else ''}")
                print("=" * 80)
    
            elif cmd.startswith("--change-url "):
                try:
                    index = int(cmd[13:]) - 1
                    if 0 <= index < len(urls):
                        print(f"[*] Changing current URL to: {urls[index]}")
                        urls[0] = urls[index]
                    else:
                        print("[!] Invalid index. Please provide a valid index.")
                except ValueError:
                    print("[!] Invalid input. Please provide a number.")

            elif cmd.startswith("--change-url "):     
                idx = int(cmd[13:].strip()) - 1
                if 0 <= idx < len(urls):
                    urls.insert(0, urls.pop(idx))
                    print(f"[*] Switched to URL: {urls[0]}")
                else:
                    print("[!] Invalid index.")

            elif cmd.startswith("--cookie "):
                cookie_str = cmd[9:].strip()
                cookies = parse_cookies(cookie_str)
                if cookies:
                    print(f"[*] Cookies set: {cookies}")
                else:
                    print("[!] Invalid cookie format. Please use 'key=value; key2=value2' format.")

            elif cmd.startswith("--payload "):
                pending_payload = cmd[10:].strip()
                print(f"[*] Payload set: {pending_payload}")
            
            elif cmd.startswith("--param "):
                param = cmd[8:].strip()
                print(f"[*] Parameter changed to: {param}")

            elif cmd.startswith("--run"):   
                if not pending_payload:
                    print("[!] No payload set. Use --payload <payload> to set a payload.")
                    continue

                for url in urls:
                    print(f"\n[*] Running injection on: {url}")
                    print(f"[*] Type: {injection_type}, Param: {param}, Payload: {pending_payload}")

                    if injection_type == "get":
                        result = inject_payload(url, param, pending_payload)
                    elif injection_type == "post":
                        # Add your POST handler here
                        result = {"info": "POST injection not yet implemented"}
                    elif injection_type == "blind":
                        # Add your blind handler here
                        result = {"info": "Blind injection not yet implemented"}
                    else:
                        result = {"error": "Unknown injection type"}

                    print(json.dumps(result, indent=2))
                    if output_file:
                        with open(output_file, "a") as f:
                            f.write(json.dumps(result) + "\n")

                else:
                    print("[!] Unknown command. Use --param, --type, --payload, --run, etc.")

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
    parser.add_argument("--param", "-p", default="filter", 
                        help="Default Parameter to inject")
    parser.add_argument("--output", "-o", required=True,
                        help="Output file for constructed requests (JSONL format)")
    parser.add_argument("--type", "-t", default="get",
                        help="Type of injection (get, post, blind)")    
    parser.add_argument("--cookies", "-c", default=None,
                        help="Cookie string to send with requests (optional)")
    
    args = parser.parse_args()
    
    # Read URLs from file
    try:
        with open(args.url_file, 'r') as f:
            urls = [line.strip() for line in f.readlines() if line.strip()]
    except Exception as e: