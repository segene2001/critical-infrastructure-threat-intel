"""
Threat Intelligence Collector
Aggregates threat data from multiple sources and normalizes to STIX 2.1 format
"""

import requests
import json
import yaml
from datetime import datetime, timedelta
from typing import List, Dict, Any
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatCollector:
    """Collects and normalizes threat intelligence from multiple sources"""
    
    def __init__(self, config_path: str = 'config/config.yaml'):
        """Initialize threat collector with configuration"""
        self.config = self._load_config(config_path)
        self.threats = []
        
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"Config file not found: {config_path}. Using defaults.")
            return self._default_config()
    
    def _default_config(self) -> Dict:
        """Return default configuration"""
        return {
            'threat_feeds': {
                'cisa_ais': {'enabled': False},
                'fs_isac': {'enabled': False},
                'osint': {'enabled': True}
            },
            'collection': {
                'interval_hours': 1,
                'lookback_days': 7
            }
        }
    
    def collect_all(self) -> List[Dict[str, Any]]:
        """Collect threats from all enabled sources"""
        logger.info("Starting threat collection from all sources...")
        
        all_threats = []
        
        # Collect from each enabled source
        if self.config['threat_feeds'].get('cisa_ais', {}).get('enabled'):
            all_threats.extend(self.collect_cisa_ais())
        
        if self.config['threat_feeds'].get('fs_isac', {}).get('enabled'):
            all_threats.extend(self.collect_fs_isac())
        
        if self.config['threat_feeds'].get('osint', {}).get('enabled'):
            all_threats.extend(self.collect_osint())
        
        # Normalize and deduplicate
        normalized_threats = self._normalize_threats(all_threats)
        deduplicated_threats = self._deduplicate(normalized_threats)
        
        logger.info(f"Collected {len(deduplicated_threats)} unique threats")
        self.threats = deduplicated_threats
        
        return deduplicated_threats
    
    def collect_cisa_ais(self) -> List[Dict[str, Any]]:
        """Collect threats from CISA AIS (Automated Indicator Sharing)"""
        logger.info("Collecting from CISA AIS...")
        
        # In production, this would connect to CISA AIS API
        # For demonstration, return sample data
        return [
            {
                'source': 'CISA_AIS',
                'threat_type': 'malware',
                'name': 'Ransomware Campaign Targeting Financial Institutions',
                'description': 'New ransomware variant targeting credit unions and community banks',
                'severity': 'critical',
                'sectors': ['financial_services'],
                'iocs': {
                    'ip_addresses': ['192.0.2.1', '198.51.100.1'],
                    'domains': ['malicious-domain.example', 'phishing-site.example'],
                    'file_hashes': ['a1b2c3d4e5f6...', 'f6e5d4c3b2a1...']
                },
                'timestamp': datetime.now().isoformat(),
                'ttps': ['T1486', 'T1566.001'],  # MITRE ATT&CK techniques
                'cve': []
            }
        ]
    
    def collect_fs_isac(self) -> List[Dict[str, Any]]:
        """Collect threats from FS-ISAC (Financial Services ISAC)"""
        logger.info("Collecting from FS-ISAC...")
        
        # In production, this would connect to FS-ISAC API
        return [
            {
                'source': 'FS_ISAC',
                'threat_type': 'fraud',
                'name': 'Wire Transfer Fraud Campaign',
                'description': 'Business email compromise targeting agricultural lenders',
                'severity': 'high',
                'sectors': ['financial_services', 'agriculture'],
                'iocs': {
                    'email_addresses': ['ceo@fake-domain.example'],
                    'domains': ['lookalike-bank.example']
                },
                'timestamp': datetime.now().isoformat(),
                'ttps': ['T1566.002'],
                'cve': []
            }
        ]
    
    def collect_osint(self) -> List[Dict[str, Any]]:
        """Collect threats from open-source intelligence"""
        logger.info("Collecting from OSINT sources...")
        
        # Sample OSINT data
        return [
            {
                'source': 'OSINT',
                'threat_type': 'vulnerability',
                'name': 'Critical Vulnerability in Agricultural IoT Devices',
                'description': 'Remote code execution vulnerability in widely-used farm sensors',
                'severity': 'critical',
                'sectors': ['agriculture'],
                'iocs': {
                    'cve': ['CVE-2024-XXXXX']
                },
                'timestamp': datetime.now().isoformat(),
                'ttps': ['T1190'],
                'affected_products': ['FarmSensor Pro v2.1', 'AgriMonitor 3000']
            }
        ]
    
    def _normalize_threats(self, threats: List[Dict]) -> List[Dict]:
        """Normalize threats to standard STIX 2.1 format"""
        normalized = []
        
        for threat in threats:
            normalized_threat = {
                'id': self._generate_threat_id(threat),
                'type': 'indicator',
                'spec_version': '2.1',
                'created': threat.get('timestamp', datetime.now().isoformat()),
                'modified': datetime.now().isoformat(),
                'name': threat.get('name', 'Unknown Threat'),
                'description': threat.get('description', ''),
                'pattern_type': 'stix',
                'valid_from': threat.get('timestamp', datetime.now().isoformat()),
                'labels': self._generate_labels(threat),
                'confidence': self._calculate_confidence(threat),
                'external_references': [{
                    'source_name': threat.get('source', 'unknown'),
                    'description': threat.get('description', '')
                }],
                'object_marking_refs': ['marking-definition--tlp-amber'],
                'custom_properties': {
                    'severity': threat.get('severity', 'medium'),
                    'sectors': threat.get('sectors', []),
                    'iocs': threat.get('iocs', {}),
                    'ttps': threat.get('ttps', []),
                    'cve': threat.get('cve', [])
                }
            }
            normalized.append(normalized_threat)
        
        return normalized
    
    def _generate_threat_id(self, threat: Dict) -> str:
        """Generate unique threat ID"""
        import hashlib
        threat_str = f"{threat.get('name', '')}{threat.get('timestamp', '')}"
        hash_obj = hashlib.md5(threat_str.encode())
        return f"indicator--{hash_obj.hexdigest()}"
    
    def _generate_labels(self, threat: Dict) -> List[str]:
        """Generate STIX labels for threat"""
        labels = []
        
        threat_type = threat.get('threat_type', '')
        if threat_type:
            labels.append(threat_type)
        
        sectors = threat.get('sectors', [])
        labels.extend(sectors)
        
        return labels
    
    def _calculate_confidence(self, threat: Dict) -> int:
        """Calculate confidence score (0-100)"""
        # Base confidence on source reliability
        source_confidence = {
            'CISA_AIS': 95,
            'FS_ISAC': 90,
            'FBI_IC3': 90,
            'OSINT': 70
        }
        
        source = threat.get('source', 'OSINT')
        return source_confidence.get(source, 60)
    
    def _deduplicate(self, threats: List[Dict]) -> List[Dict]:
        """Remove duplicate threats"""
        seen_ids = set()
        unique_threats = []
        
        for threat in threats:
            threat_id = threat['id']
            if threat_id not in seen_ids:
                seen_ids.add(threat_id)
                unique_threats.append(threat)
        
        logger.info(f"Removed {len(threats) - len(unique_threats)} duplicates")
        return unique_threats
    
    def save_threats(self, output_path: str = 'data/threats.json'):
        """Save collected threats to file"""
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(self.threats, f, indent=2)
        
        logger.info(f"Saved {len(self.threats)} threats to {output_path}")
    
    def get_threats_by_sector(self, sector: str) -> List[Dict]:
        """Filter threats by sector"""
        return [
            t for t in self.threats 
            if sector in t.get('custom_properties', {}).get('sectors', [])
        ]
    
    def get_critical_threats(self) -> List[Dict]:
        """Get only critical severity threats"""
        return [
            t for t in self.threats 
            if t.get('custom_properties', {}).get('severity') == 'critical'
        ]


def main():
    """Main execution function"""
    collector = ThreatCollector()
    
    # Collect all threats
    threats = collector.collect_all()
    
    # Save to file
    collector.save_threats()
    
    # Display summary
    print(f"\n{'='*60}")
    print(f"Threat Intelligence Collection Summary")
    print(f"{'='*60}")
    print(f"Total Threats Collected: {len(threats)}")
    print(f"Critical Threats: {len(collector.get_critical_threats())}")
    print(f"\nThreats by Sector:")
    print(f"  Financial Services: {len(collector.get_threats_by_sector('financial_services'))}")
    print(f"  Agriculture: {len(collector.get_threats_by_sector('agriculture'))}")
    print(f"{'='*60}\n")


if __name__ == '__main__':
    main()
