AI-Assisted DPI Signature Analysis Pipeline

This project provides a powerful, two-stage pipeline for analyzing network traffic (.pcap files) to identify applications and intelligently generate new signatures for unknown traffic. It combines the pattern-recognition strengths of a traditional Machine Learning model with the contextual understanding and refinement capabilities of a Large Language Model (LLM).

Key Features
Automated PCAP Analysis: Uses Zeek (or its predecessor, Bro) to automatically process raw network captures and extract key metadata like SNI, JA3/JA3S, ALPN, and initial data payloads.

Two-Stage Signature Generation:

ML Discovery: A pre-trained Keras/TensorFlow model and DBSCAN clustering perform an initial, rapid analysis to generate baseline signatures for unknown traffic.

LLM Refinement & Discovery: A more sophisticated script uses an LLM (via Ollama) and real-world domain intelligence to refine, consolidate, and expand the signature database.

Domain Intelligence: Automatically performs WHOIS lookups on unknown domains to discover their owners, enabling the script to intelligently group related services together.

Interactive Refinement: Presents clear, human-readable suggestions for database changes (e.g., "Merge 'GoogleAds' into 'YouTube'") and waits for user approval before modifying any signature files.

Robust Environment Checks: A pre-flight check runs at startup to validate all dependencies (Zeek, Ollama, Python libraries) and network connectivity, ensuring the environment is correctly configured.

The Analysis Workflow
The entire pipeline is controlled by the run_pipeline.sh script, which executes the two main stages in sequence.

Stage 1: ML-Based Discovery (v3.py)
Packet Processing: The script uses the scapy library to read .pcap files directly.

Initial Classification: A pre-trained Keras/TensorFlow model attempts to classify traffic based on its features.

Unknown Traffic Clustering: Any traffic that cannot be identified with high confidence is collected. The DBSCAN clustering algorithm is used to group these unknown flows based on their features (port, payload length, domain characteristics, etc.).

Heuristic Signature Generation: The script analyzes these clusters and uses a set of heuristic rules to automatically generate a baseline of new signatures.

Output: The results are saved to a file named ml_generated_signatures.json.

Stage 2: LLM-Based Refinement & Discovery (dpi_llm_pipeline.py)
This stage performs a more nuanced, context-aware analysis.

Load All Signatures: The script loads your manual signatures (signature.json), the existing AI-generated signatures (new_signatures.json), and is ready to incorporate the new ML-generated ones.

Triage Unmatched Flows: It re-analyzes the PCAP using the full signature set and separates all "unmatched" flows into two categories:

"True Unknowns": Flows without a domain name (identified only by JA3S, payload, etc.).

"Potential Relatives": Flows with a new, unrecognized domain name.

LLM Discovery (on "True Unknowns"): The script sends the "True Unknowns" to the LLM, asking it to act as an expert and invent a brand-new signature from scratch. The results are saved to new_signatures.json.

Domain Intelligence (on "Potential Relatives"): The script performs WHOIS lookups on the new domains to find their owners.

Suggestion Generation: Based on the ownership data, the script generates three types of suggestions:

MERGE: If two existing signatures are found to belong to the same company.

ADD: If a new domain is found to belong to a company with an existing signature.

CREATE NEW: If a new domain belongs to a company with no existing signatures.

User Confirmation: All refinement suggestions are presented to the user for a final (y/n) approval before any signature files are modified.

Setup and Installation
This project is designed to run in a Linux environment (including WSL on Windows).

1. Directory and File Setup:

Place your .pcap or .pcapng files inside the my_pcaps/ directory.

Your manually curated, high-confidence signatures should be in signature.json.

The script will automatically create and manage new_signatures.json and ml_generated_signatures.json.

2. Create a Python Virtual Environment:
This is the recommended way to manage the project's dependencies.

# From your project directory
python3 -m venv .venv

3. Activate the Virtual Environment:
You must do this every time you open a new terminal to work on the project.

source .venv/bin/activate

Your terminal prompt should now start with (.venv).

4. Install Required Libraries:
With the environment active, install all necessary Python packages with this single command:

pip install tensorflow scapy numpy scikit-learn python-whois ollama

5. Install External Dependencies:

Zeek/Bro: You must have the Zeek or Bro network analyzer installed and available in your system's PATH.

Ollama: You must have Ollama installed, and the service must be running.

How to Run
Make sure your virtual environment is active (source .venv/bin/activate).

Ensure the Ollama service is running.

Execute the master control script:

bash run_pipeline.sh

The script will first run the ML analysis and then proceed to the LLM analysis, prompting you to select a PCAP file and to approve any refinement suggestions it discovers.