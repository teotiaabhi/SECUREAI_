"""Direct test: check if worker_scan_file hangs on a Python file."""
import sys
import time
import signal
import threading

# Add backend to path
sys.path.insert(0, ".")

# Test file content - a typical Python file that might trigger many rules
TEST_CONTENT = '''
import os
import subprocess
import pickle
import yaml

def execute_command(user_input):
    """Runs a command from user input (dangerous!)."""
    result = subprocess.call(user_input, shell=True)
    os.system(user_input)
    return result

def load_data(data):
    return pickle.loads(data)

def parse_yaml(raw):
    return yaml.load(raw)

password = "hardcoded_secret_123"
api_key = "AKIA1234567890ABCDEF"

def sql_query(user_input):
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    return query

def render_html(user_input):
    return "<div>" + user_input + "</div>"

eval(input("Enter expression: "))
exec(compile(input(), "<string>", "exec"))
'''

def main():
    from engine.rule_loader import get_rule_index
    from engine.pipeline import _serialize_rules
    from engine.worker import worker_init, worker_scan_file
    
    print("Loading rules...", flush=True)
    t0 = time.monotonic()
    rule_index = get_rule_index()
    t1 = time.monotonic()
    print(f"Rules loaded: {len(rule_index.all_rules)} in {t1-t0:.2f}s", flush=True)
    
    print("Serializing rules...", flush=True)
    rules_data = _serialize_rules(rule_index.all_rules)
    t2 = time.monotonic()
    print(f"Serialized in {t2-t1:.2f}s", flush=True)
    
    print("Initializing worker...", flush=True)
    worker_init(rules_data)
    t3 = time.monotonic()
    print(f"Worker initialized in {t3-t2:.2f}s", flush=True)
    
    print(f"\nScanning test file ({len(TEST_CONTENT)} bytes)...", flush=True)
    
    # Run scan with a watchdog timer
    result = [None]
    error = [None]
    
    def do_scan():
        try:
            result[0] = worker_scan_file(TEST_CONTENT, "test_vulnerable.py", "python")
        except Exception as e:
            error[0] = e
    
    thread = threading.Thread(target=do_scan)
    thread.start()
    thread.join(timeout=60)  # 60 second timeout
    
    if thread.is_alive():
        print("HANG DETECTED: worker_scan_file did not complete in 60 seconds!", flush=True)
        # Print thread stack trace
        import traceback
        for tid, frame in sys._current_frames().items():
            if tid != threading.current_thread().ident:
                print(f"\n=== Thread {tid} stack trace ===", flush=True)
                traceback.print_stack(frame)
        sys.exit(1)
    
    t4 = time.monotonic()
    
    if error[0]:
        print(f"ERROR: {error[0]}", flush=True)
        sys.exit(1)
    
    findings = result[0]
    print(f"Scan completed in {t4-t3:.2f}s", flush=True)
    print(f"Found {len(findings)} findings", flush=True)
    for f in findings[:5]:
        print(f"  - {f.get('rule_id', '?')}: {f.get('vulnerability_type', '?')} (line {f.get('line', '?')})", flush=True)
    if len(findings) > 5:
        print(f"  ... and {len(findings)-5} more", flush=True)

if __name__ == "__main__":
    main()
