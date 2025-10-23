"""
Threat Intelligence Analyzer
AI/ML-powered threat analysis, classification, and prioritization
"""

import json
import logging
from typing import List, Dict, Any
from datetime import datetime
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatAnalyzer:
    """Analyzes and prioritizes threats using AI/ML techniques"""
    
    def __init__(self):
        """Initialize threat analyzer"""
        self.analyzed_threats = []
        
        # Threat scoring weights
        self.scoring_weights = {
            'severity': 0.35,
            'confidence': 0.25,
            'sector_relevance': 0.20,
            'recency': 0.10,
            'ioc_count': 0.10
        }
        
        # Sector-specific threat patterns
        self.sector_patterns = {
            'financial_services': {
                'high_risk_ttps': ['T1486', 'T1566', 'T1078', 'T1110'],  # Ransomware, phishing, valid accounts, brute force
                'critical_keywords': ['wire fraud', 'ransomware', 'credential theft', 'insider threat']
            },
            'agriculture': {
                'high_risk_ttps': ['T1190', 'T1498', 'T1200'],  # Exploit public-facing, DoS, hardware additions
                'critical_keywords': ['iot', 'supply chain', 'scada', 'operational technology']
            }
        }
    
    def analyze(self, threats: List[Dict], sector: str = None) -> List[Dict]:
        """Analyze threats and calculate risk scores"""
        logger.info(f"Analyzing {len(threats)} threats...")
        
        analyzed = []
        
        for threat in threats:
            # Calculate risk score
            risk_score = self._calculate_risk_score(threat, sector)
            
            # Classify threat
            classification = self._classify_threat(threat, sector)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(threat, sector)
            
            # Enrich threat data
            analyzed_threat = {
                **threat,
                'analysis': {
                    'risk_score': risk_score,
                    'priority': self._get_priority(risk_score),
                    'classification': classification,
                    'recommendations': recommendations,
                    'analyzed_at': datetime.now().isoformat(),
                    'sector_relevance': self._calculate_sector_relevance(threat, sector)
                }
            }
            
            analyzed.append(analyzed_threat)
        
        # Sort by risk score (highest first)
        analyzed.sort(key=lambda x: x['analysis']['risk_score'], reverse=True)
        
        self.analyzed_threats = analyzed
        logger.info(f"Analysis complete. {len(analyzed)} threats analyzed.")
        
        return analyzed
    
    def _calculate_risk_score(self, threat: Dict, sector: str = None) -> float:
        """Calculate overall risk score (0-100)"""
        scores = {}
        
        # Severity score
        severity_map = {'critical': 100, 'high': 75, 'medium': 50, 'low': 25}
        severity = threat.get('custom_properties', {}).get('severity', 'medium')
        scores['severity'] = severity_map.get(severity, 50)
        
        # Confidence score
        scores['confidence'] = threat.get('confidence', 60)
        
        # Sector relevance score
        scores['sector_relevance'] = self._calculate_sector_relevance(threat, sector)
        
        # Recency score (newer threats score higher)
        scores['recency'] = self._calculate_recency_score(threat)
        
        # IOC count score (more indicators = higher confidence)
        scores['ioc_count'] = self._calculate_ioc_score(threat)
        
        # Calculate weighted average
        risk_score = sum(
            scores[key] * self.scoring_weights[key] 
            for key in scores
        )
        
        return round(risk_score, 2)
    
    def _calculate_sector_relevance(self, threat: Dict, sector: str = None) -> float:
        """Calculate how relevant threat is to specific sector"""
        if not sector:
            return 50.0
        
        relevance_score = 0.0
        
        # Check if threat explicitly targets this sector
        threat_sectors = threat.get('custom_properties', {}).get('sectors', [])
        if sector in threat_sectors:
            relevance_score += 50.0
        
        # Check for sector-specific TTPs
        threat_ttps = threat.get('custom_properties', {}).get('ttps', [])
        sector_ttps = self.sector_patterns.get(sector, {}).get('high_risk_ttps', [])
        
        matching_ttps = set(threat_ttps) & set(sector_ttps)
        if matching_ttps:
            relevance_score += 30.0
        
        # Check for sector-specific keywords
        description = threat.get('description', '').lower()
        keywords = self.sector_patterns.get(sector, {}).get('critical_keywords', [])
        
        matching_keywords = [kw for kw in keywords if kw in description]
        if matching_keywords:
            relevance_score += 20.0
        
        return min(relevance_score, 100.0)
    
    def _calculate_recency_score(self, threat: Dict) -> float:
        """Calculate score based on threat recency"""
        try:
            created = datetime.fromisoformat(threat.get('created', '').replace('Z', '+00:00'))
            age_days = (datetime.now() - created.replace(tzinfo=None)).days
            
            # Newer threats score higher
            if age_days <= 1:
                return 100.0
            elif age_days <= 7:
                return 80.0
            elif age_days <= 30:
                return 60.0
            elif age_days <= 90:
                return 40.0
            else:
                return 20.0
        except:
            return 50.0
    
    def _calculate_ioc_score(self, threat: Dict) -> float:
        """Calculate score based on number of IOCs"""
        iocs = threat.get('custom_properties', {}).get('iocs', {})
        
        total_iocs = sum(
            len(v) if isinstance(v, list) else 1 
            for v in iocs.values()
        )
        
        # More IOCs = higher confidence
        if total_iocs >= 10:
            return 100.0
        elif total_iocs >= 5:
            return 75.0
        elif total_iocs >= 3:
            return 50.0
        elif total_iocs >= 1:
            return 25.0
        else:
            return 0.0
    
    def _classify_threat(self, threat: Dict, sector: str = None) -> Dict[str, Any]:
        """Classify threat into categories"""
        threat_type = threat.get('custom_properties', {}).get('threat_type', 'unknown')
        ttps = threat.get('custom_properties', {}).get('ttps', [])
        
        classification = {
            'type': threat_type,
            'category': self._get_threat_category(threat_type, ttps),
            'attack_vectors': self._identify_attack_vectors(ttps),
            'target_assets': self._identify_target_assets(threat, sector)
        }
        
        return classification
    
    def _get_threat_category(self, threat_type: str, ttps: List[str]) -> str:
        """Determine threat category"""
        if threat_type == 'malware':
            if any(ttp.startswith('T1486') for ttp in ttps):
                return 'ransomware'
            return 'malware'
        elif threat_type == 'fraud':
            return 'financial_fraud'
        elif threat_type == 'vulnerability':
            return 'exploitation'
        else:
            return 'other'
    
    def _identify_attack_vectors(self, ttps: List[str]) -> List[str]:
        """Identify attack vectors from TTPs"""
        vectors = []
        
        vector_mapping = {
            'T1566': 'phishing',
            'T1190': 'exploit_public_facing',
            'T1078': 'valid_accounts',
            'T1110': 'brute_force',
            'T1200': 'hardware_additions'
        }
        
        for ttp in ttps:
            for key, vector in vector_mapping.items():
                if ttp.startswith(key):
                    vectors.append(vector)
        
        return vectors
    
    def _identify_target_assets(self, threat: Dict, sector: str = None) -> List[str]:
        """Identify likely target assets"""
        assets = []
        
        if sector == 'financial_services':
            assets = ['core_banking', 'wire_transfer', 'customer_data', 'authentication_systems']
        elif sector == 'agriculture':
            assets = ['iot_devices', 'supply_chain_systems', 'financial_systems', 'operational_technology']
        else:
            assets = ['network_infrastructure', 'endpoints', 'data_systems']
        
        return assets
    
    def _generate_recommendations(self, threat: Dict, sector: str = None) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        severity = threat.get('custom_properties', {}).get('severity', 'medium')
        threat_type = threat.get('custom_properties', {}).get('threat_type', '')
        ttps = threat.get('custom_properties', {}).get('ttps', [])
        
        # Severity-based recommendations
        if severity == 'critical':
            recommendations.append("IMMEDIATE ACTION REQUIRED: Activate incident response team")
            recommendations.append("Implement emergency blocking of known IOCs")
        
        # Threat type-specific recommendations
        if threat_type == 'malware' or 'T1486' in ttps:
            recommendations.append("Verify backup integrity and offline backup availability")
            recommendations.append("Review and test ransomware response procedures")
            recommendations.append("Implement network segmentation to limit lateral movement")
        
        if threat_type == 'fraud' or 'T1566' in ttps:
            recommendations.append("Conduct phishing awareness training for staff")
            recommendations.append("Implement email authentication (SPF, DKIM, DMARC)")
            recommendations.append("Review wire transfer authorization procedures")
        
        if threat_type == 'vulnerability':
            recommendations.append("Conduct vulnerability scan for affected systems")
            recommendations.append("Apply security patches immediately")
            recommendations.append("Implement compensating controls if patching not possible")
        
        # Sector-specific recommendations
        if sector == 'financial_services':
            recommendations.append("Review FFIEC Cybersecurity Assessment Tool controls")
            recommendations.append("Notify FS-ISAC of threat indicators")
        
        if sector == 'agriculture':
            recommendations.append("Review IoT device security configurations")
            recommendations.append("Assess supply chain partner security posture")
        
        # General recommendations
        recommendations.append("Update SIEM correlation rules with new IOCs")
        recommendations.append("Document threat in incident tracking system")
        
        return recommendations
    
    def _get_priority(self, risk_score: float) -> str:
        """Determine priority level from risk score"""
        if risk_score >= 80:
            return 'critical'
        elif risk_score >= 60:
            return 'high'
        elif risk_score >= 40:
            return 'medium'
        else:
            return 'low'
    
    def get_threats_by_priority(self, priority: str) -> List[Dict]:
        """Filter threats by priority level"""
        return [
            t for t in self.analyzed_threats 
            if t['analysis']['priority'] == priority
        ]
    
    def generate_summary_report(self) -> Dict[str, Any]:
        """Generate summary report of analyzed threats"""
        if not self.analyzed_threats:
            return {}
        
        priority_counts = defaultdict(int)
        sector_counts = defaultdict(int)
        type_counts = defaultdict(int)
        
        for threat in self.analyzed_threats:
            priority = threat['analysis']['priority']
            priority_counts[priority] += 1
            
            sectors = threat.get('custom_properties', {}).get('sectors', [])
            for sector in sectors:
                sector_counts[sector] += 1
            
            threat_type = threat.get('custom_properties', {}).get('threat_type', 'unknown')
            type_counts[threat_type] += 1
        
        avg_risk_score = sum(
            t['analysis']['risk_score'] for t in self.analyzed_threats
        ) / len(self.analyzed_threats)
        
        return {
            'total_threats': len(self.analyzed_threats),
            'average_risk_score': round(avg_risk_score, 2),
            'priority_distribution': dict(priority_counts),
            'sector_distribution': dict(sector_counts),
            'type_distribution': dict(type_counts),
            'critical_threats': len(self.get_threats_by_priority('critical')),
            'high_threats': len(self.get_threats_by_priority('high')),
            'generated_at': datetime.now().isoformat()
        }
    
    def save_analysis(self, output_path: str = 'data/analyzed_threats.json'):
        """Save analyzed threats to file"""
        from pathlib import Path
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(self.analyzed_threats, f, indent=2)
        
        logger.info(f"Saved {len(self.analyzed_threats)} analyzed threats to {output_path}")


def main():
    """Main execution function"""
    # Load collected threats
    try:
        with open('data/threats.json', 'r') as f:
            threats = json.load(f)
    except FileNotFoundError:
        logger.error("No threats found. Run threat_collector.py first.")
        return
    
    # Analyze threats
    analyzer = ThreatAnalyzer()
    
    # Analyze for financial services
    fs_threats = analyzer.analyze(threats, sector='financial_services')
    
    # Generate summary
    summary = analyzer.generate_summary_report()
    
    # Save analysis
    analyzer.save_analysis()
    
    # Display report
    print(f"\n{'='*60}")
    print(f"Threat Intelligence Analysis Report")
    print(f"{'='*60}")
    print(f"Total Threats Analyzed: {summary['total_threats']}")
    print(f"Average Risk Score: {summary['average_risk_score']}")
    print(f"\nPriority Distribution:")
    for priority, count in summary['priority_distribution'].items():
        print(f"  {priority.capitalize()}: {count}")
    print(f"\nSector Distribution:")
    for sector, count in summary['sector_distribution'].items():
        print(f"  {sector}: {count}")
    print(f"\nThreat Type Distribution:")
    for threat_type, count in summary['type_distribution'].items():
        print(f"  {threat_type}: {count}")
    print(f"{'='*60}\n")
    
    # Display top 3 critical threats
    critical = analyzer.get_threats_by_priority('critical')
    if critical:
        print(f"\nTop Critical Threats:")
        print(f"{'-'*60}")
        for i, threat in enumerate(critical[:3], 1):
            print(f"\n{i}. {threat['name']}")
            print(f"   Risk Score: {threat['analysis']['risk_score']}")
            print(f"   Recommendations:")
            for rec in threat['analysis']['recommendations'][:3]:
                print(f"   - {rec}")


if __name__ == '__main__':
    main()
