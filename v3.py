
import pickle
import numpy as np
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
from scapy.all import rdpcap, conf
from scapy.layers.inet import TCP, IP, UDP
from scapy.layers.tls.all import TLS, TLSClientHello
from scapy.packet import Raw
import time
from collections import defaultdict, Counter
import argparse
import logging
import sys
import os
import signal
import struct
import threading
from datetime import datetime
import re
import binascii
import json
import hashlib
from sklearn.cluster import DBSCAN
import warnings
from sklearn.exceptions import InconsistentVersionWarning

# --- Environment Setup to Reduce Log Noise ---
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
# ---

# Enhanced logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dpi.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Suppress non-critical Scapy warnings about unknown cipher suites
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


class UnknownTrafficCollector:
    """Collects and analyzes unknown traffic patterns for signature generation."""

    def __init__(self, storage_path="unknown_traffic.json", min_confidence=0.3):
        self.storage_path = storage_path
        self.min_confidence = min_confidence
        self.unknown_samples = []
        self.pattern_cache = {}
        self.load_unknown_samples()

    def load_unknown_samples(self):
        """Load previously collected unknown samples."""
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, 'r') as f:
                    self.unknown_samples = json.load(f)
                logger.info(f"Loaded {len(self.unknown_samples)} unknown samples")
            except Exception as e:
                logger.error(f"Error loading unknown samples: {e}")
                self.unknown_samples = []

    def save_unknown_samples(self):
        """Save unknown samples to disk."""
        try:
            with open(self.storage_path, 'w') as f:
                json.dump(self.unknown_samples, f, indent=2)
            logger.debug(f"Saved {len(self.unknown_samples)} unknown samples")
        except Exception as e:
            logger.error(f"Error saving unknown samples: {e}")

    def add_unknown_sample(self, src_ip, dst_ip, sni, port, confidence,
                           payload_features, timestamp):
        """Add a new unknown traffic sample."""
        sample = {
            'id': hashlib.md5(f"{sni}:{port}:{timestamp}".encode()).hexdigest()[:8],
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'sni': sni,
            'port': port,
            'confidence': confidence,
            'payload_length': payload_features.get('payload_length', 0),
            'protocol': payload_features.get('protocol', 'unknown'),
            'payload_hex': payload_features.get('payload_hex', '')[:200],  # Truncate for storage
            'domain_info': self.extract_domain_features(sni) if sni else None
        }

        self.unknown_samples.append(sample)

        # Auto-save every 10 samples
        if len(self.unknown_samples) % 10 == 0:
            self.save_unknown_samples()

    def extract_domain_features(self, sni):
        """Extract features from domain name."""
        if not sni:
            return None

        features = {
            'domain': sni,
            'tld': sni.split('.')[-1] if '.' in sni else None,
            'subdomain_count': len(sni.split('.')) - 2,
            'length': len(sni),
            'has_numbers': bool(re.search(r'\d', sni)),
            'has_hyphens': '-' in sni,
            'entropy': self.calculate_entropy(sni)
        }

        # Check for common patterns
        if re.search(r'(api|cdn|static|media|assets)', sni):
            features['likely_service'] = 'api_or_cdn'
        elif re.search(r'(mail|smtp|pop|imap)', sni):
            features['likely_service'] = 'email'
        elif re.search(r'(video|stream|media)', sni):
            features['likely_service'] = 'streaming'

        return features

    def calculate_entropy(self, text):
        """Calculate Shannon entropy of text."""
        if not text:
            return 0

        prob = [float(text.count(c)) / len(text) for c in set(text)]
        entropy = -sum([p * np.log2(p) for p in prob if p > 0])
        return entropy

    def cluster_unknown_samples(self, min_samples=3):
        """Cluster unknown samples to find potential new applications."""
        if len(self.unknown_samples) < min_samples:
            logger.warning(f"Not enough samples for clustering: {len(self.unknown_samples)}")
            return {}

        # Prepare features for clustering
        features = []
        sample_ids = []

        for sample in self.unknown_samples:
            if sample['sni']:
                # Create feature vector
                domain_features = sample.get('domain_info', {})
                feature_vector = [
                    domain_features.get('length', 0),
                    domain_features.get('subdomain_count', 0),
                    domain_features.get('entropy', 0),
                    sample['port'],
                    sample['payload_length'],
                    int(domain_features.get('has_numbers', False)),
                    int(domain_features.get('has_hyphens', False))
                ]
                features.append(feature_vector)
                sample_ids.append(sample['id'])

        if len(features) < min_samples:
            return {}

        # Perform clustering
        features_array = np.array(features)
        clustering = DBSCAN(eps=0.5, min_samples=min_samples).fit(features_array)

        # Group samples by cluster
        clusters = defaultdict(list)
        for i, label in enumerate(clustering.labels_):
            if label != -1:  # -1 indicates noise
                clusters[label].append(self.unknown_samples[i])

        logger.info(f"Found {len(clusters)} clusters from {len(features)} samples")
        return dict(clusters)

    def generate_signature_from_sample(self, sample):
        """Generate a signature from a single sample in the specified format."""
        sni = sample['sni']
        if not sni:
            return None

        parts = sni.split('.')
        if len(parts) < 2:
            return None

        base_domain = '.'.join(parts[-2:])
        signature_name = self.auto_label_sni(sni)

        # Generate signature in the same format as the 'ajio' example
        return {
            signature_name: {
                'sni_patterns': [
                    re.escape(sni),  # Exact match
                    f"(?:.*\\.)?{re.escape(base_domain)}",  # Wildcard for base domain
                    f"(?:.*\\.)?www\\.{re.escape(base_domain)}",  # www subdomain
                    f"(?:.*\\.)?api\\.{re.escape(base_domain)}",  # api subdomain
                    f"(?:.*\\.)?assets\\.{re.escape(base_domain)}",  # assets subdomain
                    f"(?:.*\\.)?capi\\.{re.escape(base_domain)}",  # capi subdomain
                    f"(?:.*\\.)?static\\.{re.escape(base_domain)}"  # static subdomain
                ],
                'ports': [sample['port']],
                'payloads': [sample['payload_hex'][:200]] if sample['payload_hex'] else []  # Full payload like ajio
            }
        }

    def auto_label_sni(self, sni):
        """Heuristic to auto-label SNI based on domain patterns."""
        if not sni:
            return "unknown"

        parts = sni.split('.')
        if len(parts) < 2:
            return "unknown"

        base_domain = parts[-2]  # e.g., 'audi' from 'www.audi.in'
        known_apps = {
            'audi': ['audi.in'],
            'ajio': ['ajio.com'],
            'youtube': ['youtube.com', 'googlevideo.com'],
            'netflix': ['netflix.com', 'nflxvideo.net']
            # Add other known apps as needed
        }

        for app, domains in known_apps.items():
            for domain in domains:
                if domain in sni:
                    return app
        return base_domain  # Default to base domain as app name

    def generate_signatures_from_clusters(self, clusters, min_cluster_size=3, is_covered_callback=None):
        """Generate potential signatures from clusters, skipping already covered SNIs."""
        potential_signatures = {}

        for cluster_id, samples in clusters.items():
            if len(samples) < min_cluster_size:
                continue

            # Analyze SNI patterns
            sni_list = [s['sni'] for s in samples if s['sni']]
            if not sni_list:
                continue

            # Check if the primary SNI for this cluster is already covered by an existing signature
            if is_covered_callback and is_covered_callback(sni_list[0]):
                logger.info(f"Skipping cluster {cluster_id} based on SNI '{sni_list[0]}' as it is already covered by an existing signature.")
                continue

            # Find common domain patterns
            common_patterns = self.find_common_domain_patterns(sni_list)

            # Analyze ports
            ports = [s['port'] for s in samples]
            common_ports = [port for port, count in Counter(ports).items() if count >= 2]

            # Analyze payload patterns
            payload_patterns = self.find_common_payload_patterns(samples)

            # Generate signature name
            signature_name = self.auto_label_sni(sni_list[0]) if sni_list else 'cluster_' + str(cluster_id)

            # Format signature to match the 'ajio' structure
            signature = {
                'sni_patterns': common_patterns,
                'ports': common_ports,
                'payloads': [pattern['pattern'].hex()[:200] for pattern in payload_patterns]
            }

            potential_signatures[signature_name] = signature

        return potential_signatures

    def find_common_domain_patterns(self, sni_list):
        """Find common patterns in domain names."""
        patterns = []

        # Find exact matches
        domain_counts = Counter(sni_list)
        for domain, count in domain_counts.items():
            if count >= 2:
                patterns.append(re.escape(domain))

        # Find wildcard patterns
        for domain in set(sni_list):
            parts = domain.split('.')
            if len(parts) >= 2:
                base_domain = '.'.join(parts[-2:])
                wildcard_pattern = f"(?:.*\\.)?{re.escape(base_domain)}"
                matching_count = sum(1 for d in sni_list if re.match(wildcard_pattern, d))
                if matching_count >= 2:
                    patterns.append(wildcard_pattern)

            # Add common subdomains
            if len(parts) > 2:
                for subdomain in ['www', 'assets', 'api', 'capi', 'static']:
                    if subdomain in parts:
                        patterns.append(f"(?:.*\\.)?{subdomain}\\.{re.escape(base_domain)}")

        return sorted(list(set(patterns)))

    def find_common_payload_patterns(self, samples):
        """Find common patterns in payload data."""
        patterns = []

        # Analyze payload prefixes
        payload_prefixes = defaultdict(int)
        for sample in samples:
            payload_hex = sample.get('payload_hex', '')
            if len(payload_hex) >= 8:
                prefix = payload_hex[:200]  # Match ajio payload length
                payload_prefixes[prefix] += 1

        # Add patterns that appear in multiple samples
        for prefix, count in payload_prefixes.items():
            if count >= 2:
                try:
                    pattern_bytes = bytes.fromhex(prefix)
                    patterns.append({
                        'pattern': pattern_bytes,
                        'type': 'raw',
                        'offset': 0,
                        'description': f'Common payload prefix (found in {count} samples)'
                    })
                except ValueError:
                    continue

        return patterns

    def update_signature_database(self, new_signatures, output_path="signatures.json"):
        """Update the existing signature database with new signatures."""
        try:
            # Load existing signatures
            existing_signatures = {}
            if os.path.exists(output_path):
                with open(output_path, 'r') as f:
                    existing_signatures = json.load(f)

            # Update with new signatures
            existing_signatures.update(new_signatures)

            # Save updated signatures
            with open(output_path, 'w') as f:
                json.dump(existing_signatures, f, indent=2)
            logger.debug(f"Updated signature database with {len(new_signatures)} new signatures to {output_path}")
        except Exception as e:
            logger.error(f"Error updating signature database: {e}")

    def get_training_data(self, label_mapping=None):
        """Convert unknown samples to training data format."""
        training_data = []

        for sample in self.unknown_samples:
            if sample['sni']:
                label = label_mapping.get(sample['id'], self.auto_label_sni(sample['sni'])) if label_mapping else self.auto_label_sni(sample['sni'])
                training_data.append({
                    'sni': sample['sni'],
                    'label': label,
                    'port': sample['port'],
                    'payload_features': {
                        'payload_length': sample['payload_length'],
                        'protocol': sample['protocol']
                    }
                })

        return training_data

class EnhancedLiveSNICapture:
    """Enhanced version of LiveSNICapture with signature discovery capabilities."""

    def __init__(self, model_path="models/cnn_classifier.h5",
                 tokenizer_path="models/1_tokenizer.pkl",
                 label_encoder_path="models/1_label_encoder.pkl",
                 confidence_threshold=0.5,
                 signature_db=None,
                 new_signatures_path="newly_generated_signatures.json"
                 ):
        self.confidence_threshold = confidence_threshold
        self.stats = defaultdict(int)
        self.unique_snis = set()
        self.running = False
        self.session_start = datetime.now()
        self.last_activity = time.time()
        self.display_interval = 5
        self.quiet_mode = False
        self.logger = logger

        # Initialize signature database
        self.signature_db = signature_db or {}
        # Store path for new signatures
        self.new_signatures_path = new_signatures_path

        # Initialize unknown traffic collector
        self.unknown_collector = UnknownTrafficCollector()

        # Load models
        self.load_models(model_path, tokenizer_path, label_encoder_path)
        self.display_thread = None

        # Periodic signature generation
        self.last_signature_generation = time.time()
        self.signature_generation_interval = 300  # 5 minutes

    def load_models(self, model_path, tokenizer_path, label_encoder_path):
        """Load ML models with proper error handling."""
        try:
            self.cnn_model = load_model(model_path)
            self.logger.info(f"✅ Model loaded: {model_path}")

            with open(tokenizer_path, "rb") as f:
                self.tokenizer = pickle.load(f)
            self.logger.info(f"✅ Tokenizer loaded: {tokenizer_path}")

            with open(label_encoder_path, "rb") as f:
                self.label_encoder = pickle.load(f)
            self.logger.info(f"✅ Label encoder loaded: {label_encoder_path}")

        except Exception as e:
            self.logger.warning(f"⚠️ ML models not available: {e}")
            self.cnn_model = None
            self.tokenizer = None
            self.label_encoder = None

    def is_sni_already_covered(self, sni_to_check):
        """Check if an SNI is already covered by the initial signature database patterns."""
        if not sni_to_check:
            return False
        # Check against the initial database (self.signature_db)
        for app, data in self.signature_db.items():
            for pattern in data.get('sni_patterns', []):
                try:
                    if re.match(pattern, sni_to_check, re.IGNORECASE):
                        self.logger.debug(f"SNI '{sni_to_check}' is already covered by pattern '{pattern}' for app '{app}'. Skipping new signature.")
                        return True
                except re.error:
                    continue
        return False

    def match_signature(self, sni=None, port=443, payload_features=None):
        """Enhanced signature matching with unknown traffic collection."""
        best_match = None
        best_confidence = 0.0

        # Try existing signature matching first
        for app, data in self.signature_db.items():
            confidence_scores = []

            # Port matching
            if port in data.get('ports', []):
                confidence_scores.append(0.3)

            # SNI pattern matching
            if sni:
                for pattern in data.get('sni_patterns', []):
                    try:
                        if re.match(pattern, sni, re.IGNORECASE):
                            confidence_scores.append(0.6)
                            break
                    except re.error as e:
                        self.logger.debug(f"[Regex Error] in {app}: {pattern} => {e}")

            # Payload pattern matching
            if payload_features and payload_features.get('raw_payload'):
                payload_patterns = data.get('payloads', [])
                if payload_patterns:
                    for pattern_hex in payload_patterns:
                        try:
                            pattern = bytes.fromhex(pattern_hex)
                            if pattern in payload_features['raw_payload']:
                                confidence_scores.append(0.4)
                                break
                        except Exception:
                            continue

            # Calculate overall confidence
            if confidence_scores:
                overall_confidence = sum(confidence_scores) / len(confidence_scores)
                if len(confidence_scores) > 1:
                    overall_confidence = min(1.0, overall_confidence * 1.2)

                if overall_confidence > best_confidence:
                    best_confidence = overall_confidence
                    best_match = app

        # If no good match found, try ML model
        if best_confidence < 0.7 and sni and self.cnn_model:
            try:
                seq = self.tokenizer.texts_to_sequences([sni])
                if seq and seq[0]:
                    padded = pad_sequences(seq, maxlen=100)
                    probs = self.cnn_model.predict(padded, verbose=0)
                    ml_confidence = float(np.max(probs))
                    if ml_confidence > best_confidence:
                        predicted_class = np.argmax(probs)
                        best_match = self.label_encoder.inverse_transform([predicted_class])[0]
                        best_confidence = ml_confidence
            except Exception as e:
                self.logger.debug(f"ML prediction error: {e}")

        return best_match or "unknown", best_confidence

    def packet_callback(self, pkt):
        """Enhanced packet callback with unknown traffic collection."""
        try:
            self.stats['total_packets'] += 1
            self.last_activity = time.time()

            if not (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
                return

            self.stats['tcp_udp_packets'] += 1
            src_ip = pkt[IP].src if pkt.haslayer(IP) else "Unknown"
            dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "Unknown"

            port = 443
            if pkt.haslayer(TCP):
                port = pkt[TCP].dport if pkt[TCP].dport in [80, 443, 8080, 8443] else pkt[TCP].sport
            elif pkt.haslayer(UDP):
                port = pkt[UDP].dport if pkt[UDP].dport in [53, 443, 8080] else pkt[UDP].sport

            payload_features = self.extract_payload_features(pkt)
            sni = None

            if port == 443 or pkt.haslayer(TLS):
                self.stats['https_packets'] += 1
                sni = self.extract_sni_from_packet(pkt)
                if sni and sni not in self.unique_snis:
                    self.unique_snis.add(sni)
                    self.stats['tls_handshakes'] += 1

            # Match against signatures
            app, confidence = self.match_signature(sni=sni, port=port, payload_features=payload_features)

            # Collect unknown traffic for analysis
            if app == "unknown" or confidence < self.confidence_threshold:
                self.unknown_collector.add_unknown_sample(
                    src_ip, dst_ip, sni, port, confidence,
                    payload_features, datetime.now().isoformat()
                )
                self.stats['unknown_traffic'] += 1

                # Generate signature for single sample, but only if not already covered
                if sni:
                    # Check if the SNI is already covered by the initial signature DB
                    if not self.is_sni_already_covered(sni):
                        sig = self.unknown_collector.generate_signature_from_sample(
                            self.unknown_collector.unknown_samples[-1]
                        )
                        if sig:
                            # Save to the new signatures file
                            self.unknown_collector.update_signature_database(sig, output_path=self.new_signatures_path)
                            for name, s in sig.items():
                                if len(s['sni_patterns']) >= 2:
                                    # Also add to in-memory DB for this session
                                    self.signature_db[name] = s
                                    self.logger.debug(f"Auto-generated and integrated new signature: {name}")

            # Log and save detections
            if confidence >= self.confidence_threshold:
                self.stats[app] += 1
                if not self.quiet_mode:
                    self.log_detection(src_ip, dst_ip, sni, app, confidence, port, payload_features)
                self.save_detection(src_ip, dst_ip, sni, app, confidence, port, payload_features)

            # Periodic signature generation
            if (time.time() - self.last_signature_generation) > self.signature_generation_interval:
                self.generate_new_signatures()
                self.last_signature_generation = time.time()

        except Exception as e:
            self.logger.debug(f"Packet processing error: {e}")

    def generate_new_signatures(self):
        """Generate new signatures from collected unknown traffic."""
        try:
            clusters = self.unknown_collector.cluster_unknown_samples()
            # Pass the checking function as a callback to prevent creating signatures for known apps
            new_signatures = self.unknown_collector.generate_signatures_from_clusters(
                clusters,
                is_covered_callback=self.is_sni_already_covered
            )
            if new_signatures:
                self.logger.info(f"Generated {len(new_signatures)} new signatures from clusters.")
                # Save to the new signatures file
                self.unknown_collector.update_signature_database(new_signatures, output_path=self.new_signatures_path)
                for name, sig in new_signatures.items():
                    if len(sig['sni_patterns']) >= 2:
                        # Also add to in-memory DB for this session
                        self.signature_db[name] = sig
                        self.logger.info(f"Auto-integrated new signature from cluster: {name}")
        except Exception as e:
            self.logger.error(f"Error generating new signatures: {e}")

    def extract_payload_features(self, packet):
        """Extract payload content for pattern matching."""
        features = {
            'raw_payload': b'',
            'payload_length': 0,
            'protocol': 'unknown',
            'payload_hex': ''
        }
        
        try:
            if packet.haslayer(Raw):
                raw_layer = packet[Raw]
                features['raw_payload'] = bytes(raw_layer)
                features['payload_length'] = len(features['raw_payload'])
                features['payload_hex'] = binascii.hexlify(features['raw_payload']).decode('utf-8')
                
            if packet.haslayer(TCP):
                features['protocol'] = 'tcp'
                tcp_layer = packet[TCP]
                if hasattr(tcp_layer, 'payload') and tcp_layer.payload:
                    tcp_payload = bytes(tcp_layer.payload)
                    if tcp_payload:
                        features['raw_payload'] = tcp_payload
                        features['payload_length'] = len(tcp_payload)
                        features['payload_hex'] = binascii.hexlify(tcp_payload).decode('utf-8')
                        
            elif packet.haslayer(UDP):
                features['protocol'] = 'udp'
                udp_layer = packet[UDP]
                if hasattr(udp_layer, 'payload') and udp_layer.payload:
                    udp_payload = bytes(udp_layer.payload)
                    if udp_payload:
                        features['raw_payload'] = udp_payload
                        features['payload_length'] = len(udp_payload)
                        features['payload_hex'] = binascii.hexlify(udp_payload).decode('utf-8')
                        
        except Exception as e:
            self.logger.debug(f"Payload extraction error: {e}")
        
        return features

    def extract_sni_from_packet(self, pkt):
        """Extract SNI using multiple methods."""
        sni = None
        
        # Try TLS layer first
        if pkt.haslayer(TLS):
            try:
                tls_layer = pkt[TLS]
                if hasattr(tls_layer, 'msg') and tls_layer.msg:
                    for msg in tls_layer.msg:
                        if hasattr(msg, 'ext') and msg.ext:
                            for ext in msg.ext:
                                if hasattr(ext, 'servernames') and ext.servernames:
                                    sni = ext.servernames[0].servername.decode('utf-8', errors='ignore')
                                    break
                            if sni:
                                break
            except:
                pass
        
        # Try TLSClientHello
        if not sni and pkt.haslayer(TLSClientHello):
            try:
                tls_hello = pkt[TLSClientHello]
                if hasattr(tls_hello, 'ext') and tls_hello.ext:
                    for ext in tls_hello.ext:
                        if hasattr(ext, 'servernames') and ext.servernames:
                            sni = ext.servernames[0].servername.decode('utf-8', errors='ignore')
                            break
            except:
                pass
        
        # Try raw extraction from TCP payload
        if not sni and pkt.haslayer(TCP):
            try:
                tcp_layer = pkt[TCP]
                if hasattr(tcp_layer, 'payload') and tcp_layer.payload:
                    raw_data = bytes(tcp_layer.payload)
                    sni = self.extract_sni_from_raw(raw_data)
            except:
                pass
        
        return sni
    
    def extract_sni_from_raw(self, raw_data):
        """Extract SNI from raw TLS data."""
        try:
            if len(raw_data) < 43 or raw_data[0] != 0x16 or raw_data[5] != 0x01:
                return None
            
            offset = 43
            if offset >= len(raw_data):
                return None
            session_id_len = raw_data[offset]
            offset += 1 + session_id_len
            
            if offset + 2 > len(raw_data):
                return None
            cipher_suites_len = struct.unpack(">H", raw_data[offset:offset+2])[0]
            offset += 2 + cipher_suites_len
            
            if offset + 1 > len(raw_data):
                return None
            compression_len = raw_data[offset]
            offset += 1 + compression_len
            
            if offset + 2 > len(raw_data):
                return None
            extensions_len = struct.unpack(">H", raw_data[offset:offset+2])[0]
            offset += 2
            
            extensions_end = offset + extensions_len
            while offset < extensions_end and offset + 4 <= len(raw_data):
                ext_type = struct.unpack(">H", raw_data[offset:offset+2])[0]
                ext_len = struct.unpack(">H", raw_data[offset+2:offset+4])[0]
                offset += 4
                
                if ext_type == 0x0000 and offset + ext_len <= len(raw_data):
                    sni_data = raw_data[offset:offset+ext_len]
                    if len(sni_data) >= 5:
                        sni_offset = 2
                        while sni_offset + 3 <= len(sni_data):
                            name_type = sni_data[sni_offset]
                            name_len = struct.unpack(">H", sni_data[sni_offset+1:sni_offset+3])[0]
                            sni_offset += 3
                            
                            if name_type == 0x00 and sni_offset + name_len <= len(sni_data):
                                hostname = sni_data[sni_offset:sni_offset+name_len].decode('utf-8', errors='ignore')
                                return hostname
                            sni_offset += name_len
                offset += ext_len
            return None
        except Exception as e:
            self.logger.debug(f"SNI extraction error: {e}")
            return None
    
    def log_detection(self, src_ip, dst_ip, sni, app, confidence, port, payload_features):
        """Log detection details."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"\n🔍 [{timestamp}] NEW CONNECTION")
        print(f"📍 {src_ip} → {dst_ip}:{port}")
        if sni:
            print(f"🌐 {sni}")
        print(f"📱 {app.upper()} ({confidence:.2f})")
        if payload_features['payload_length'] > 0:
            print(f"📦 Payload: {payload_features['payload_length']} bytes ({payload_features['protocol']})")
        print("-" * 50)
    
    def save_detection(self, src_ip, dst_ip, sni, app, confidence, port, payload_features):
        """Save detection to CSV."""
        timestamp = datetime.now().isoformat()
        payload_len = payload_features['payload_length'] if payload_features else 0
        protocol = payload_features['protocol'] if payload_features else 'unknown'
        with open('detections.csv', 'a') as f:
            f.write(f"{timestamp},{src_ip},{dst_ip},{sni or 'N/A'},{app},{confidence:.3f},{port},{payload_len},{protocol}\n")
    
    def print_live_stats(self):
        """Print enhanced live statistics and a final summary report."""
        if self.quiet_mode:
            return
        elapsed = datetime.now() - self.session_start
        print(f"\n📊 ANALYSIS STATS - {elapsed}")
        print(f"📦 Packets Processed: {self.stats['total_packets']}")
        print(f"🔗 TCP/UDP: {self.stats['tcp_udp_packets']}")
        print(f"🔒 HTTPS: {self.stats['https_packets']}")
        print(f"🌐 Unique Domains: {len(self.unique_snis)}")
        print(f"❓ Unknown Traffic: {self.stats['unknown_traffic']}")
        print(f"🔍 Collected Samples: {len(self.unknown_collector.unknown_samples)}")
        
        app_stats = {k: v for k, v in self.stats.items() 
                     if k not in ['total_packets', 'tcp_udp_packets', 'https_packets', 'tls_handshakes', 'unknown_traffic']}
        if app_stats:
            top_apps = sorted(app_stats.items(), key=lambda x: x[1], reverse=True)[:5]
            print("📱 Top Apps:")
            for app, count in top_apps:
                print(f"   • {app}: {count}")
        
        # --- NEW: Final Summary Report ---
        print("\n" + "="*40)
        print("📜 Signature Generation Summary")
        print("="*40)
        
        num_generated = 0
        if os.path.exists(self.new_signatures_path):
            try:
                with open(self.new_signatures_path, 'r') as f:
                    content = f.read()
                    if content:
                        # Re-open to read from the start
                        f.seek(0)
                        generated_sigs = json.load(f)
                        num_generated = len(generated_sigs)
            except (json.JSONDecodeError, IOError):
                pass
                
        print(f"📄 Total New Signatures Generated: {num_generated}")
        if num_generated > 0:
            print(f"   - Saved to: {self.new_signatures_path}")
        print("="*40)
    
    def generate_signature_report(self):
        """Generate a comprehensive signature discovery report."""
        clusters = self.unknown_collector.cluster_unknown_samples()
        signatures = self.unknown_collector.generate_signatures_from_clusters(clusters)
        
        string_keyed_clusters = {str(k): v for k, v in clusters.items()}
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_unknown_samples': len(self.unknown_collector.unknown_samples),
            'clusters_found': len(clusters),
            'signatures_generated': len(signatures),
            'clusters': string_keyed_clusters,
            'signatures': signatures
        }
        
        with open('signature_discovery_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Signature discovery report saved to signature_discovery_report.json")
        return report

    def process_pcap_directory(self, pcap_dir, bpf_filter="tcp port 443 or udp"):
        """Process selected pcap files from a given directory."""
        self.running = True

        # Initialize CSV file with headers
        if not os.path.exists('detections.csv'):
            with open('detections.csv', 'w') as f:
                f.write("timestamp,src_ip,dst_ip,sni,application,confidence,port,payload_length,protocol\n")
        
        if not os.path.isdir(pcap_dir):
            logger.error(f"Directory not found: {pcap_dir}")
            return

        all_pcap_files = [os.path.join(pcap_dir, f) for f in os.listdir(pcap_dir) if f.endswith(('.pcap', '.pcapng'))]
        if not all_pcap_files:
            logger.error(f"No .pcap or .pcapng files found in {pcap_dir}")
            return

        # --- NEW FEATURE: User selection ---
        print("\n" + "="*50)
        print("📁 Available PCAP files for analysis:")
        for i, f in enumerate(all_pcap_files, 1):
            print(f"  [{i}] {os.path.basename(f)}")
        print("="*50)
        
        selected_files = []
        while not selected_files:
            try:
                choice = input("👉 Enter the number(s) of the files to process (e.g., 1,3 or 'all'): ")
                if not choice.strip():
                    print("⚠️ Please make a selection.")
                    continue

                if choice.lower() == 'all':
                    selected_files = all_pcap_files
                    break

                indices = [int(i.strip()) - 1 for i in choice.split(',')]
                
                # Validate indices
                valid_indices = []
                invalid_choices = []
                for i in indices:
                    if 0 <= i < len(all_pcap_files):
                        valid_indices.append(i)
                    else:
                        invalid_choices.append(i + 1)

                if invalid_choices:
                    print(f"❌ Invalid choice(s): {', '.join(map(str, invalid_choices))}. Please select from the list.")
                    continue # Re-prompt
                
                # Get the actual file paths from valid indices, avoiding duplicates
                selected_files = list(dict.fromkeys([all_pcap_files[i] for i in valid_indices]))

            except ValueError:
                print("❌ Invalid input. Please enter numbers separated by commas or 'all'.")
                continue

        if not selected_files:
            logger.info("No files selected. Exiting.")
            return
        # --- END NEW FEATURE ---

        logger.info(f"Starting analysis of {len(selected_files)} selected pcap file(s)...")

        try:
            total_packets = 0
            # Use the user-selected list of files
            for pcap_file in selected_files:
                logger.info(f"Processing file: {pcap_file}")
                # Use a generator for memory efficiency with large files
                packets = rdpcap(pcap_file)
                for packet in packets:
                    if "tcp port 443" in bpf_filter and packet.haslayer(TCP) and (packet[TCP].sport == 443 or packet[TCP].dport == 443):
                        self.packet_callback(packet)
                    elif "udp" in bpf_filter and packet.haslayer(UDP):
                        self.packet_callback(packet)
                
                total_packets += len(packets)
                logger.info(f"Finished processing {os.path.basename(pcap_file)}. Analyzed {len(packets)} packets.")
            
            logger.info(f"Completed analysis of all files. Total packets analyzed: {total_packets}")

        except Exception as e:
            logger.error(f"Pcap processing error: {e}")
        finally:
            self.stop_processing()
    
    def stop_processing(self):
        """Stop the analysis and save final data."""
        self.running = False
        self.unknown_collector.save_unknown_samples()
        
        # Generate final signature report and save new signatures
        self.generate_new_signatures()
        self.generate_signature_report()
        
        logger.info("Processing stopped.")
        self.print_live_stats()

def main():
    """Main function with enhanced signature discovery."""
    parser = argparse.ArgumentParser(description="Enhanced DPI with signature discovery from PCAP files.")
    parser.add_argument('-d', '--directory', type=str, default="my_pcaps",
                        help="Directory containing pcap files to process (default: my_pcaps)")
    parser.add_argument('-f', '--filter', type=str, default="tcp port 443 or udp",
                        help="BPF filter string")
    parser.add_argument('-c', '--confidence', type=float, default=0.5,
                        help="Confidence threshold for classifications")
    parser.add_argument('-s', '--signatures', type=str, default="signatures.json",
                        help="Path to the input signature database JSON file (default: signatures.json)")
    parser.add_argument('-o', '--output-signatures', type=str, default="ml_generated_signatures.json",
                        help="Path to save the newly discovered signatures (default: ml_generated_signatures.json)")
    parser.add_argument('--generate-report', action='store_true',
                        help="Generate signature discovery report and exit")
    
    args = parser.parse_args()
    
    # Load signature database
    signature_db = {}
    if os.path.exists(args.signatures):
        try:
            with open(args.signatures, 'r') as f:
                signature_db = json.load(f)
            logger.info(f"Loaded signature database with {len(signature_db)} apps from {args.signatures}")
        except Exception as e:
            logger.error(f"Error loading signature database: {e}")
    
    capture = EnhancedLiveSNICapture(
        confidence_threshold=args.confidence,
        signature_db=signature_db,
        new_signatures_path=args.output_signatures
    )
    
    if args.generate_report:
        report = capture.generate_signature_report()
        print(f"Generated signature discovery report with {report['signatures_generated']} new signatures")
        return
    
    try:
        # Start processing from the directory instead of live capture
        capture.process_pcap_directory(
            pcap_dir=args.directory,
            bpf_filter=args.filter
        )
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received. Stopping...")
        capture.stop_processing()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        capture.stop_processing()
        sys.exit(1)

if __name__ == "__main__":
    main()
