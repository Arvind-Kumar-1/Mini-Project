import os
import re
import json
import subprocess
from collections import defaultdict
import socket
import time

# --- Configuration ---
MASTER_SIGNATURES_PATH = "signature.json"
CANDIDATE_SIGNATURES_PATH = "ml_generated_signatures.json"
OLLAMA_MODEL = "llama3"

# --- WHOIS and Domain Intelligence ---

def get_whois_registrant(domain, cache):
    """Performs a WHOIS lookup with a global timeout and caching."""
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

# --- LLM Naming Function ---

def get_llm_name_suggestion(domains, model):
    """Queries the LLM to get a good, human-readable name for a new signature."""
    print(f"   - Asking LLM for a name for domains: {domains[:2]}...")
    prompt = (
        "Based on the following list of related domain names, what is the single, most common, human-readable name for the application or company they represent?\n"
        "For example, if the domains are ['googlevideo.com', 'youtube.com'], the answer should be 'YouTube'.\n"
        "Respond with ONLY the name and nothing else.\n\n"
        f"Domains: {domains}"
    )
    try:
        proc = subprocess.Popen(['ollama','run',model], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
        out, err = proc.communicate(input=prompt)
        if out: return out.strip().replace('"', '')
    except Exception:
        return None

# --- Main Workflow Functions ---

def pre_filter_candidates(candidates, master_db):
    """
    Performs a fast pass to reject obvious duplicates and gather domains for investigation.
    """
    print("\n🔬 Step 1: Pre-filtering candidate signatures...")
    duplicates = []
    to_investigate = {} # domain -> candidate_signature_data

    # Create a pre-compiled list of all patterns from the master DB for efficiency
    all_master_patterns = []
    for sig_data in master_db.values():
        all_master_patterns.extend(sig_data.get('sni_patterns', []))

    for name, data in candidates.items():
        is_duplicate = False
        primary_domain = None
        for pattern in data.get('sni_patterns', []):
            domain = clean_domain_from_pattern(pattern)
            if not domain: continue
            primary_domain = domain # Use the first clean domain as the key

            # Check against master patterns
            for master_pattern in all_master_patterns:
                if re.search(master_pattern, domain, re.IGNORECASE):
                    duplicates.append({'name': name, 'reason': f"Domain '{domain}' is already covered."})
                    is_duplicate = True
                    break
            if is_duplicate:
                break
        
        if not is_duplicate and primary_domain:
            to_investigate[primary_domain] = {'name': name, 'data': data}
            
    print(f"✅ Pre-filtering complete. Found {len(duplicates)} duplicates.")
    return duplicates, to_investigate

def build_master_ownership_index(master_db, whois_cache):
    """
    Builds an in-memory index mapping owners to their signature names.
    """
    print("\n Indexing master signature database by owner...")
    owner_to_primary_sig = {}

    for name, data in master_db.items():
        # Find the first valid domain to determine ownership
        for pattern in data.get('sni_patterns', []):
            domain = clean_domain_from_pattern(pattern)
            if domain:
                owner = get_whois_registrant(domain, whois_cache)
                if owner != "Unknown":
                    # Use the first signature found for an owner as the "primary"
                    if owner not in owner_to_primary_sig:
                        owner_to_primary_sig[owner] = name
                break # Only need to check one domain per signature
    
    print(f"✅ Master index created.")
    return owner_to_primary_sig

def make_automated_decisions(to_investigate, master_owner_index, whois_cache):
    """
    Performs batch WHOIS lookups and makes automated ADD or CREATE NEW decisions.
    """
    print("\n🤖 Step 2 & 3: Performing batch WHOIS lookups and making decisions...")
    
    # Enrich candidates with ownership info
    candidate_owners = defaultdict(list)
    for domain, candidate_data in to_investigate.items():
        owner = get_whois_registrant(domain, whois_cache)
        if owner != "Unknown":
            candidate_owners[owner].append(candidate_data)

    add_actions = defaultdict(list)
    create_new_actions = defaultdict(list)

    # Make decisions
    for owner, candidates in candidate_owners.items():
        if owner in master_owner_index:
            # Owner exists, so we ADD to their primary signature
            primary_sig_name = master_owner_index[owner]
            for candidate in candidates:
                add_actions[primary_sig_name].extend(candidate['data'].get('sni_patterns', []))
        else:
            # This is a new owner, so we CREATE a new signature
            all_domains = []
            for candidate in candidates:
                for pattern in candidate['data'].get('sni_patterns', []):
                    domain = clean_domain_from_pattern(pattern)
                    if domain: all_domains.append(domain)
            
            if all_domains:
                create_new_actions[owner].extend(all_domains)

    print("✅ Automated decisions complete.")
    return add_actions, create_new_actions

def apply_changes_and_report(add_actions, create_new_actions, duplicates, model):
    """Applies all changes to the master signature file and prints a detailed final report."""
    print(f"\n💾 Applying changes to {MASTER_SIGNATURES_PATH}...")
    
    master_db = {}
    if os.path.exists(MASTER_SIGNATURES_PATH):
        with open(MASTER_SIGNATURES_PATH, 'r', encoding='utf-8') as f:
            try: master_db = json.load(f)
            except json.JSONDecodeError: pass

    updated_sigs = []
    created_sigs = []

    # Apply ADD actions
    for sig_name, patterns_to_add in add_actions.items():
        if sig_name in master_db:
            updated_sigs.append(sig_name)
            existing_patterns = set(master_db[sig_name].get('sni_patterns', []))
            existing_patterns.update(patterns_to_add)
            master_db[sig_name]['sni_patterns'] = sorted(list(existing_patterns))

    # Apply CREATE NEW actions
    for owner, domains in create_new_actions.items():
        suggested_name = get_llm_name_suggestion(domains, model) or owner
        if suggested_name not in master_db:
            created_sigs.append(suggested_name)
            master_db[suggested_name] = {
                "ports": [443],
                "sni_patterns": sorted([f"^{re.escape(d)}$" for d in set(domains)])
            }

    # Write the updated database back
    with open(MASTER_SIGNATURES_PATH, 'w', encoding='utf-8') as f:
        json.dump(master_db, f, indent=2, ensure_ascii=False)

    # --- New Detailed Final Report ---
    print("\n" + "="*40)
    print("🤖 Automated Signature Merge Complete")
    print("="*40)
    
    if updated_sigs or created_sigs:
        print("\n[✅ Signatures Added or Updated]")
        for name in updated_sigs:
            print(f"  - UPDATED: '{name}'")
        for name in created_sigs:
            print(f"  - CREATED: '{name}'")
    
    if duplicates:
        print("\n[❌ Signatures Rejected]")
        for item in duplicates:
            print(f"  - REJECTED: '{item['name']}' (Reason: {item['reason']})")

    print("\n" + "="*40)
    print(f"✅ Master signature database ({MASTER_SIGNATURES_PATH}) has been updated.")

    # --- NEW: Cleanup Step ---
    try:
        if os.path.exists(CANDIDATE_SIGNATURES_PATH):
            with open(CANDIDATE_SIGNATURES_PATH, 'w', encoding='utf-8') as f:
                json.dump({}, f) # Write an empty JSON object to clear the file
            print(f"✅ Cleared processed signatures from candidate file: {CANDIDATE_SIGNATURES_PATH}")
    except OSError as e:
        print(f"⚠️ Could not clear candidate file {CANDIDATE_SIGNATURES_PATH}: {e}")


def main():
    """Main workflow for the signature merging tool."""
    print("--- Starting Automated Signature Verification and Merge Tool ---")
    
    # Check if candidate file exists before starting
    if not os.path.exists(CANDIDATE_SIGNATURES_PATH):
        print(f"🟡 No candidate signature file found at '{CANDIDATE_SIGNATURES_PATH}'. Nothing to merge.")
        return

    try:
        with open(MASTER_SIGNATURES_PATH, 'r') as f:
            master_db = json.load(f)
        with open(CANDIDATE_SIGNATURES_PATH, 'r') as f:
            candidate_db = json.load(f)
    except FileNotFoundError as e:
        print(f"❌ Error: Could not find a required signature file: {e.filename}")
        return
    except json.JSONDecodeError:
        print(f"❌ Error: Could not parse a signature file. Please ensure it is valid JSON.")
        return

    duplicates, to_investigate = pre_filter_candidates(candidate_db, master_db)
    
    whois_cache = {}
    master_owner_index = build_master_ownership_index(master_db, whois_cache)

    add_actions, create_new_actions = make_automated_decisions(to_investigate, master_owner_index, whois_cache)

    apply_changes_and_report(add_actions, create_new_actions, duplicates, OLLAMA_MODEL)

if __name__ == "__main__":
    main()
