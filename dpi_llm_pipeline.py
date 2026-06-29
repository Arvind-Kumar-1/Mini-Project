import os
import re
import json
import subprocess
import tempfile
import shutil
from collections import defaultdict, Counter
from datetime import datetime
import time
import socket # Import the socket library to control timeouts

# --- Zeek Integration Functions ---

def run_zeek_on_pcap(pcap_path):
    """
    Runs Zeek on a given PCAP file, loading a custom script to extract payloads.
    """
    zeek_path = shutil.which('zeek') or shutil.which('bro')
    if not zeek_path:
        print("❌ 'zeek' or 'bro' command not found in your environment.")
        return None

    script_dir = os.path.dirname(os.path.realpath(__file__))
    payload_script_path = os.path.join(script_dir, 'extract_payload.zeek')

    if not os.path.exists(payload_script_path):
        print(f"❌ Custom Zeek script '{payload_script_path}' not found. Please create it.")
        return None

    absolute_pcap_path = os.path.abspath(pcap_path)
    log_dir = tempfile.mkdtemp()
    print(f"🚀 Running Zeek on {os.path.basename(pcap_path)} with payload extraction...")
    
    try:
        subprocess.run(
            [zeek_path, "-C", "-r", absolute_pcap_path, payload_script_path],
            cwd=log_dir,
            check=True,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        print("✅ Zeek analysis complete.")
        return log_dir
    except subprocess.CalledProcessError as e:
        print(f"❌ Error running Zeek. It might have failed to process the PCAP.")
        print(f"   Stderr: {e.stderr}")
        shutil.rmtree(log_dir)
        return None
    except Exception as e:
        print(f"❌ An unexpected error occurred while running Zeek: {e}")
        shutil.rmtree(log_dir)
        return None

def parse_zeek_log(log_path):
    if not os.path.exists(log_path): return []
    entries = []
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Could not read log file {log_path}: {e}")
        return []
    header_line_index = -1
    for i, line in enumerate(lines):
        if line.startswith('#fields'):
            header_line_index = i
            break
    if header_line_index == -1: return []
    fields = lines[header_line_index].strip().split('\t')[1:]
    for line in lines[header_line_index + 1:]:
        if line.startswith('#') or not line.strip(): continue
        values = line.strip().split('\t')
        entries.append(dict(zip(fields, values)))
    return entries

def process_zeek_logs(log_dir):
    print("Processing and correlating Zeek logs...")
    conn_log = parse_zeek_log(os.path.join(log_dir, 'conn.log'))
    ssl_log = parse_zeek_log(os.path.join(log_dir, 'ssl.log'))
    dns_log = parse_zeek_log(os.path.join(log_dir, 'dns.log'))
    payload_log = parse_zeek_log(os.path.join(log_dir, 'payload_content.log'))

    ssl_map = {entry['uid']: entry for entry in ssl_log}
    dns_map = defaultdict(list)
    for entry in dns_log:
        for uid in entry.get('uids', '').split(','):
             if uid and uid != '-':
                    dns_map[uid].append(entry)
    payload_map = {entry['uid']: entry for entry in payload_log}

    flows = []
    for conn in conn_log:
        uid = conn['uid']
        flow = {
            'uid': uid,
            'src': conn['id.orig_h'],
            'dst': conn['id.resp_h'],
            'port': int(conn['id.resp_p']),
            'service': conn.get('service', 'unknown'),
            'duration': float(conn.get('duration', '0.0').replace('-', '0')),
        }
        if uid in ssl_map:
            ssl_info = ssl_map[uid]
            flow['sni'] = ssl_info.get('server_name')
            flow['alpn'] = ssl_info.get('alpn')
            flow['ja3'] = ssl_info.get('ja3')
            flow['ja3s'] = ssl_info.get('ja3s')
            flow['certificate_subject'] = ssl_info.get('subject')
        if uid in dns_map:
            flow['dns_queries'] = list(set(d.get('query') for d in dns_map[uid] if d.get('query')))
        if uid in payload_map:
            flow['payload_hex'] = payload_map[uid].get('payload_hex')
        flows.append(flow)
    print(f"✅ Correlated {len(flows)} connection flows.")
    return flows

# --- Signature and Matching Functions ---

def load_signature_patterns(path='signature.json', source_tag='manual'):
    """
    Loads signature patterns and adds a safety check for malformed entries.
    """
    if not os.path.exists(path): return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = f.read().strip()
            if not data: return {}
            sigs = json.loads(data)
    except (FileNotFoundError, json.JSONDecodeError):
        print(f"⚠️ Could not parse {path}. It might be empty or malformed.")
        return {}

    clean_sigs = {}
    for site, entry in sigs.items():
        if isinstance(entry, dict):
            entry['source'] = source_tag
            clean_sigs[site] = entry
        else:
            print(f"⚠️ Skipping malformed signature '{site}' in {path}. Expected a dictionary, but got {type(entry).__name__}.")
            
    print(f"✅ Loaded {len(clean_sigs)} valid signatures from {path}")
    return clean_sigs

def match_flow_to_site(flow, signatures):
    for site, sig in signatures.items():
        if sig.get('ports') and flow.get('port') not in sig['ports']:
            continue
        
        def check_patterns(patterns, value):
            if not value: return False
            for p in patterns or []:
                try:
                    if re.search(p, value, re.IGNORECASE):
                        return True
                except re.error:
                    continue
            return False

        if check_patterns(sig.get('sni_patterns'), flow.get('sni')):
            flow['matched_by'] = 'sni'
            flow['signature_source'] = sig.get('source')
            return site
        
        if check_patterns(sig.get('alpn_patterns'), flow.get('alpn')):
            flow['matched_by'] = 'alpn'
            flow['signature_source'] = sig.get('source')
            return site

        if flow.get('ja3s') and flow['ja3s'] in sig.get('ja3s_hashes', []):
            flow['matched_by'] = 'ja3s'
            flow['signature_source'] = sig.get('source')
            return site

    flow['matched_by'] = 'unknown'
    flow['signature_source'] = 'unknown'
    return "unknown"

# --- LLM Discovery Workflow ---

def group_discovery_flows(flows):
    g = defaultdict(list)
    for flow in flows:
        key = flow.get('ja3s') or f"payload_port:{flow['port']}"
        g[key].append(flow)
    return g

def build_discovery_prompt(groups):
    prompt = (
        "You are a network signature expert. Your task is to propose DPI signatures for unidentified network flows that lack domain names.\n"
        "Focus on strong indicators like JA3S hashes and payload patterns.\n"
        "**RULES FOR SIGNATURE CREATION**:\n"
        "1. **JA3S IS CRITICAL**: If a group shares a unique JA3S hash, you SHOULD create a signature for it.\n"
        "2. **PRIORITIZE INDICATORS** in this order: 1. `ja3s_hashes`, 2. `payload_patterns`.\n"
        "Return ONLY a single, raw JSON array of objects. Do not include any other text. Give a descriptive name for the application.\n"
        'Example: [ { "SomeGameClient": { "ja3s_hashes": ["e7d0b6338e32e8d3b3c8172321a8023a"] } } ]\n\n'
    )
    for key, flows in groups.items():
        prompt += f"# Group Key: {key}\n"
        prompt += f"   - Flow Count: {len(flows)}\n"
        sample_payloads = list(set(f.get('payload_hex') for f in flows if f.get('payload_hex')))
        if sample_payloads: prompt += f"   - Sample Payloads (Hex): {sample_payloads[:3]}\n"
        prompt += "\n"
    return prompt

# --- Domain Intelligence and Refinement Workflow ---

def get_whois_registrant(domain, cache):
    """Performs a WHOIS lookup using the python-whois library with a global timeout and retry mechanism."""
    if domain in cache:
        return cache[domain]
    
    print(f"   - Performing WHOIS lookup for: {domain}")
    original_timeout = socket.getdefaulttimeout()
    try:
        import whois
        socket.setdefaulttimeout(15)
        w = whois.whois(domain)
        org = w.org
        if org:
            if isinstance(org, list): org = org[0]
            org = org.replace(" Inc.", "").replace(", Inc", "").replace(" LLC", "").replace(" Ltd.", "").strip()
            cache[domain] = org
            return org
            
    except Exception as e:
        print(f"     └── ❌ WHOIS lookup failed for {domain}: {e}")
    finally:
        socket.setdefaulttimeout(original_timeout)
    
    cache[domain] = "Unknown"
    return "Unknown"

def clean_domain_from_pattern(pattern):
    """Strips common regex characters to get a clean domain for WHOIS lookups."""
    domain = pattern.strip('^$')
    domain = re.sub(r'^\(\?:\\\.\*\)\?', '', domain)
    domain = domain.replace('\\.', '.')
    domain = domain.replace('\\-', '-')
    if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
        return None
    return domain

def gather_domain_intelligence(unmatched_flows, whois_cache):
    print("\n🔍 Gathering Domain Intelligence for unmatched flows with SNI...")
    unique_domains = set()
    for flow in unmatched_flows:
        if flow.get('sni') and not is_ip_address(flow['sni']):
            unique_domains.add(flow['sni'])
    
    owner_map = defaultdict(list)
    for domain in sorted(list(unique_domains)):
        owner = get_whois_registrant(domain, whois_cache)
        if owner != "Unknown":
            owner_map[owner].append(domain)
    
    print(f"✅ Found {len(owner_map)} unique domain owners among unmatched flows.")
    return owner_map

def generate_refinement_suggestions(owner_map, signatures, whois_cache):
    print("\n🧠 Generating Refinement Suggestions...")
    owner_to_sig_names = defaultdict(list)
    for sig_name, sig_data in signatures.items():
        for sni_pattern in sig_data.get('sni_patterns', []):
            domain = clean_domain_from_pattern(sni_pattern)
            if domain:
                owner = get_whois_registrant(domain, whois_cache)
                if owner != "Unknown" and sig_name not in owner_to_sig_names[owner]:
                    owner_to_sig_names[owner].append(sig_name)

    merge_suggestions, add_suggestions, create_new_suggestions = [], defaultdict(list), defaultdict(list)

    for owner, sig_names in owner_to_sig_names.items():
        if len(sig_names) > 1:
            primary_sig = sig_names[0]
            for other_sig in sig_names[1:]:
                merge_suggestions.append({'from': other_sig, 'to': primary_sig, 'reason': f"Both are owned by {owner}"})

    for owner, domains in owner_map.items():
        if owner in owner_to_sig_names:
            primary_sig = owner_to_sig_names[owner][0]
            for domain in domains:
                is_covered = any(re.search(p, domain, re.IGNORECASE) for p in signatures.get(primary_sig, {}).get('sni_patterns', []))
                if not is_covered:
                    add_suggestions[primary_sig].append(domain)
        else:
            create_new_suggestions[owner].extend(domains)
            
    return merge_suggestions, add_suggestions, create_new_suggestions

def build_naming_prompt(domains):
    return (
        "Based on the following list of related domain names, what is the single, most common, human-readable name for the application or company they represent?\n"
        "For example, if the domains are ['googlevideo.com', 'youtube.com'], the answer should be 'YouTube'.\n"
        "Respond with ONLY the name and nothing else.\n\n"
        f"Domains: {domains}"
    )

def get_llm_name_suggestion(domains, model):
    print(f"   - Asking LLM for a name for domains: {domains[:2]}...")
    prompt = build_naming_prompt(domains)
    try:
        proc = subprocess.Popen(['ollama','run',model], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
        out, err = proc.communicate(input=prompt)
        if out: return out.strip().replace('"', '')
    except Exception: return None

def present_and_apply_suggestions(merge, add, create_new, model, manual_db_path, llm_db_path):
    print("\n" + "="*40)
    print("🤖 AI Signature Refinement Suggestions")
    print("="*40)
    
    has_suggestions = False
    if merge:
        has_suggestions = True
        print("\n[MERGE Suggestions]")
        for s in merge: print(f"  - Merge '{s['from']}' into '{s['to']}' (Reason: {s['reason']})")
    
    if add:
        has_suggestions = True
        print("\n[ADD to Existing Signature Suggestions]")
        for sig_name, domains in add.items():
            print(f"  - To '{sig_name}':")
            for domain in domains: print(f"    - Add SNI pattern for: {domain}")

    create_new_processed = {}
    if create_new:
        has_suggestions = True
        print("\n[CREATE NEW Signature Suggestions]")
        for owner, domains in create_new.items():
            suggested_name = get_llm_name_suggestion(domains, model) or owner
            print(f"  - For owner '{owner}' (domains: {domains[:2]}...):")
            print(f"    - Suggested Name: '{suggested_name}'")
            create_new_processed[owner] = {'name': suggested_name, 'domains': domains}
            
    if not has_suggestions:
        print("\nNo new refinement opportunities found in this run.")
        return create_new_processed # Return empty dict

    print("\n" + "="*40)
    try:
        confirm = input("Apply these refinement changes? (y/n): ").lower()
        if confirm == 'y':
            apply_refinement_to_database(merge, add, create_new_processed, manual_db_path, llm_db_path)
        else:
            print("Refinement changes discarded.")
    except KeyboardInterrupt:
        print("\nOperation cancelled. Refinement changes discarded.")
    
    return create_new_processed

def apply_refinement_to_database(merge, add, create_new, manual_path, llm_path):
    """
    Applies refinement suggestions ONLY to the LLM-generated database.
    Advises the user on changes for the manual database.
    """
    print(f"\n💾 Applying refinement changes to {llm_path}...")
    
    manual_db = {}
    if os.path.exists(manual_path):
        with open(manual_path, 'r', encoding='utf-8') as f:
            try: manual_db = json.load(f)
            except json.JSONDecodeError: pass

    llm_db = {}
    if os.path.exists(llm_path):
        with open(llm_path, 'r', encoding='utf-8') as f:
            try: llm_db = json.load(f)
            except json.JSONDecodeError: print(f"⚠️ Malformed {llm_path}, will be overwritten.")

    # 1. Handle MERGE suggestions
    for s in merge:
        print(f"   - Manual Action Recommended: Consider merging '{s['from']}' into '{s['to']}' in {manual_path}.")

    # 2. Handle ADD suggestions
    for sig_name, domains in add.items():
        if sig_name in manual_db:
            print(f"   - Manual Action Recommended: Consider adding domains {domains} to '{sig_name}' in {manual_path}.")
        elif sig_name in llm_db:
            print(f"   - Adding domains to '{sig_name}' in {llm_path}...")
            patterns = set(llm_db[sig_name].get('sni_patterns', []))
            for domain in domains: patterns.add(f"^{re.escape(domain)}$")
            llm_db[sig_name]['sni_patterns'] = sorted(list(patterns))

    # 3. Handle CREATE NEW suggestions
    for owner, data in create_new.items():
        name = data['name']
        if name not in llm_db and name not in manual_db:
            print(f"   - Creating new signature '{name}' in {llm_path}...")
            llm_db[name] = {"ports": [443], "sni_patterns": sorted([f"^{re.escape(d)}$" for d in data['domains']])}
    
    with open(llm_path, 'w', encoding='utf-8') as f:
        json.dump(llm_db, f, indent=2, ensure_ascii=False)
    print(f"✅ LLM signature database ({llm_path}) updated.")

# --- General LLM and Utility Functions ---

def query_ollama(prompt, model='llama3'):
    try:
        import ollama
        print(f"🚀 Querying Ollama with model '{model}' (JSON mode)...")
        response = ollama.generate(model=model, prompt=prompt, format='json', stream=False)
        return response['response']
    except ImportError:
        print("⚠️ 'ollama' library not found. Falling back to subprocess method.")
    except Exception:
        print("   Falling back to subprocess method.")
    try:
        print(f"🚀 Querying Ollama with model '{model}' (subprocess)...")
        proc = subprocess.Popen(['ollama','run',model], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
        out, err = proc.communicate(input=prompt)
        return out.strip() if not err else ""
    except Exception: return ""

def extract_json_block(text):
    if not text: return None
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            for key in ["signature", "signatures", "results", "data"]:
                if key in data and isinstance(data[key], list):
                    data = data[key]
                    break
        merged_data = {}
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict): merged_data.update(item)
        elif isinstance(data, dict):
            merged_data.update(data)
        return merged_data if merged_data else None
    except json.JSONDecodeError: return None

def is_ip_address(s):
    if not s: return False
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s.split(':')[0]))

def test_whois_connectivity():
    """
    Performs a direct socket connection to a known WHOIS server to test connectivity.
    """
    print("   - Testing direct WHOIS connectivity...")
    try:
        with socket.create_connection(("whois.verisign-grs.com", 43), timeout=10) as sock:
            print("   ✅ WHOIS Connectivity Check: Successfully connected to port 43.")
            return True
    except Exception as e:
        print("   ❌ Check Failed: Could not connect to WHOIS server on port 43.")
        print(f"      Reason: {e}")
        print("      This may be due to a firewall on your machine, router, or network.")
        return False

def run_pre_flight_checks(model='llama3'):
    print("🚦 Running Pre-Flight Checks...")
    checks_passed = True
    if not (shutil.which('zeek') or shutil.which('bro')):
        print("❌ Check Failed: 'zeek' or 'bro' command not found.")
        checks_passed = False
    else:
        print("✅ Zeek/Bro Check: Found.")
    if not shutil.which('ollama'):
        print("❌ Check Failed: 'ollama' command not found.")
        checks_passed = False
    else:
        print("✅ Ollama Command Check: Found.")
    try:
        import ollama
        print("✅ Ollama Library Check: 'ollama' Python library is installed.")
    except ImportError:
        print("🟡 Check Warning: 'ollama' Python library not found. For best results: pip install ollama")
    
    try:
        import whois
        print("✅ WHOIS Library Check: 'python-whois' library is installed.")
        if not test_whois_connectivity():
            checks_passed = False
    except ImportError:
        print("🟡 Check Warning: 'python-whois' library not found. This is required for domain refinement.")
        print("   - Please install the library with: pip install python-whois")
        checks_passed = False

    if not os.path.exists('my_pcaps'):
        print("🟡 Check Warning: 'my_pcaps' directory not found. Creating it now.")
        os.makedirs('my_pcaps')
    print("-" * 20)
    if not checks_passed:
        print("❌ Pre-flight checks failed. Please resolve issues.")
    else:
        print("✅ All pre-flight checks passed.\n")
    return checks_passed

def generate_summary_report(all_flows, discovered_sigs, refinement_sugs):
    """Generates a text summary report of the analysis run."""
    report_lines = []
    report_lines.append("📊 Traffic Classification Summary 📊\n" + "="*35)
    
    grouped_by_site = defaultdict(list)
    for flow in all_flows:
        grouped_by_site[flow.get('site', 'unknown')].append(flow)
    
    sorted_sites = sorted(grouped_by_site.items(), key=lambda item: len(item[1]), reverse=True)
    for site, site_flows in sorted_sites:
        flow_count = len(site_flows)
        report_lines.append(f"📡 Site: {site} ({flow_count} flows)")
        matched_by_counter = Counter(f['matched_by'] for f in site_flows)
        source_counter = Counter(f['signature_source'] for f in site_flows)
        report_lines.append(f"     Matched By: {dict(matched_by_counter)}")
        report_lines.append(f"     Signature Source: {dict(source_counter)}")
        report_lines.append("-" * 20)

    if discovered_sigs:
        report_lines.append("\n🔬 LLM Discovery Results 🔬\n" + "="*28)
        report_lines.append(f"✅ Discovered {len(discovered_sigs)} new signature(s) for non-domain traffic.")
        for name in discovered_sigs.keys():
            report_lines.append(f"  - {name}")

    if any(refinement_sugs.values()):
        report_lines.append("\n🤖 AI Signature Refinement Suggestions 🤖\n" + "="*38)
        for sug_type, sugs in refinement_sugs.items():
            if sugs:
                report_lines.append(f"\n[{sug_type.upper()} Suggestions]")
                if sug_type == 'merge':
                    for s in sugs:
                        report_lines.append(f"  - Merge '{s['from']}' into '{s['to']}' (Reason: {s['reason']})")
                elif sug_type == 'add':
                    for s in sugs:
                        for sig_name, domains in s.items():
                            report_lines.append(f"  - To '{sig_name}': add {', '.join(domains)}")
                elif sug_type == 'create_new':
                     for s in sugs:
                        for owner, data in s.items():
                            report_lines.append(f"  - For owner '{owner}': create new signature '{data['name']}'")

    return "\n".join(report_lines)

# --- Main Analysis Pipeline ---

def analyze_pcap_file(pcap_path, model, signatures):
    run_timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    pcap_basename = os.path.splitext(os.path.basename(pcap_path))[0]
    outputs_dir = "outputs"
    os.makedirs(outputs_dir, exist_ok=True)

    log_dir = run_zeek_on_pcap(pcap_path)
    if not log_dir: return
    
    all_flows = process_zeek_logs(log_dir)
    shutil.rmtree(log_dir)
    
    if not all_flows:
        print("No processable connection flows found in the PCAP.")
        return
    
    matched_flows, unmatched_flows = [], []
    for flow in all_flows:
        site = match_flow_to_site(flow, signatures)
        flow['site'] = site
        if site == 'unknown':
            unmatched_flows.append(flow)
        else:
            matched_flows.append(flow)

    # --- Triage and Run Workflows ---
    flows_with_sni = [f for f in unmatched_flows if f.get('sni')]
    flows_without_sni = [f for f in unmatched_flows if not f.get('sni')]
    
    ja3s_to_site_map = {}
    for site, sig_data in signatures.items():
        for ja3s_hash in sig_data.get('ja3s_hashes', []):
            ja3s_to_site_map[ja3s_hash] = site

    truly_unknown_flows = []
    reclassified_count = 0
    for flow in flows_without_sni:
        ja3s = flow.get('ja3s')
        if ja3s and ja3s in ja3s_to_site_map:
            site = ja3s_to_site_map[ja3s]
            flow['site'] = site
            flow['matched_by'] = 'ja3s (reverse lookup)'
            flow['signature_source'] = signatures[site].get('source')
            matched_flows.append(flow)
            reclassified_count += 1
        else:
            truly_unknown_flows.append(flow)
    
    if reclassified_count > 0:
        print(f"\n✅ Re-classified {reclassified_count} non-domain flow(s) using existing JA3S signatures.")

    print(f"\n⚡ Classification Stats for {os.path.basename(pcap_path)}:")
    print(f"- Total flows: {len(all_flows)}")
    print(f"- Matched by rules: {len(matched_flows)} ({len(matched_flows)/len(all_flows) if all_flows else 0:.1%})")
    final_unmatched_count = len(all_flows) - len(matched_flows)
    print(f"- Remaining Unmatched: {final_unmatched_count} ({final_unmatched_count/len(all_flows) if all_flows else 0:.1%})")
    
    discovered_sigs = {}
    refinement_suggestions = {}

    # 1. Discovery Workflow for TRULY unknown non-domain traffic
    if truly_unknown_flows:
        print("\n🕵️‍♂️ Starting Discovery on non-domain traffic...")
        discovery_groups = group_discovery_flows(truly_unknown_flows)
        if discovery_groups:
            prompt = build_discovery_prompt(discovery_groups)
            raw_out = query_ollama(prompt, model)
            if raw_out:
                discovered_sigs = extract_json_block(raw_out) or {}
                if discovered_sigs:
                    discovered_filename = f"{outputs_dir}/{pcap_basename}_discovered_signatures_{run_timestamp}.json"
                    with open(discovered_filename, 'w') as f: json.dump(discovered_sigs, f, indent=2)
                    print(f"✅ Raw discovered signatures saved to → {discovered_filename}")
                    
                    llm_db_path = 'new_signatures.json'
                    llm_db = {}
                    if os.path.exists(llm_db_path):
                        try:
                            with open(llm_db_path, 'r') as f:
                                content = f.read()
                                if content:
                                    llm_db = json.loads(content)
                        except json.JSONDecodeError:
                            print(f"⚠️ Malformed {llm_db_path}, will be overwritten.")
                    
                    llm_db.update(discovered_sigs)
                    with open(llm_db_path, 'w') as f: json.dump(llm_db, f, indent=2)
                    print(f"✅ Updated {llm_db_path} with {len(discovered_sigs)} new signature(s).")

    # 2. Refinement Workflow for domain-based traffic
    if flows_with_sni:
        whois_cache = {}
        owner_map = gather_domain_intelligence(flows_with_sni, whois_cache)
        if owner_map:
            merge, add, create_new = generate_refinement_suggestions(owner_map, signatures, whois_cache)
            # This returns the processed suggestions with names from the LLM
            processed_creations = present_and_apply_suggestions(merge, add, create_new, model, 'signature.json', 'new_signatures.json')
            refinement_suggestions = {'merge': merge, 'add': [add], 'create_new': [processed_creations]}

    # --- Save Output Files ---
    matched_filename = f"{outputs_dir}/{pcap_basename}_matched_{run_timestamp}.json"
    unmatched_filename = f"{outputs_dir}/{pcap_basename}_unmatched_{run_timestamp}.json"
    summary_filename = f"{outputs_dir}/{pcap_basename}_summary_{run_timestamp}.txt"
    
    with open(matched_filename, 'w', encoding='utf-8') as f: json.dump(matched_flows, f, indent=2)
    print(f"\n✅ Matched flow details saved to → {matched_filename}")

    final_unmatched_flows = truly_unknown_flows + flows_with_sni
    with open(unmatched_filename, 'w', encoding='utf-8') as f: json.dump(final_unmatched_flows, f, indent=2)
    print(f"✅ Unmatched flow details saved to → {unmatched_filename}")
    
    summary_report = generate_summary_report(all_flows, discovered_sigs, refinement_suggestions)
    with open(summary_filename, 'w', encoding='utf-8') as f:
        f.write(summary_report)
    print(f"✅ Summary report saved to → {summary_filename}")
    
    print(f"\n✅ Analysis Complete.")

# --- Main Execution Block ---

if __name__ == "__main__":
    model = 'llama3'
    if not run_pre_flight_checks(model): exit(1)
    
    manual_signatures = load_signature_patterns('signature.json', source_tag='manual')
    llm_signatures = load_signature_patterns('new_signatures.json', source_tag='llm')
    all_signatures = {**manual_signatures, **llm_signatures}
    
    print(f"\nLoaded a total of {len(all_signatures)} signatures for this run.")
    
    pcaps = [f for f in os.listdir('my_pcaps') if f.lower().endswith(('.pcap','.pcapng'))]
    if not pcaps:
        print("No .pcap or .pcapng files found in the 'my_pcaps' directory.")
        exit(1)
    
    print("\nSelect a PCAP file to analyze:")
    for i, fn in enumerate(pcaps, 1):
        print(f"   [{i}] {fn}")
    
    selected_index = -1
    while not (0 <= selected_index < len(pcaps)):
        try:
            sel_input = input("Enter number: ")
            selected_index = int(sel_input) - 1
        except (ValueError, IndexError):
            print("Invalid selection.")
            
    selected_pcap_file = os.path.join('my_pcaps', pcaps[selected_index])
    analyze_pcap_file(selected_pcap_file, model, all_signatures)
    print("\nThank you for using the DPI LLM Pipeline! 🚀")