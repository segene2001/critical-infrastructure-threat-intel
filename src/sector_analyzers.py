"""
Sector-Specific Threat Analyzers
Specialized analysis for Financial Services and Agriculture sectors
"""

import logging
from typing import List, Dict, Any
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FinancialServicesAnalyzer:
    """Specialized threat analyzer for financial services sector"""
    
    def __init__(self):
        """Initialize financial services analyzer"""
        self.compliance_frameworks = {
            'FFIEC': {
                'name': 'FFIEC Cybersecurity Assessment Tool',
                'controls': ['access_control', 'data_protection', 'incident_response']
            },
            'FCA': {
                'name': 'Farm Credit Administration Requirements',
                'controls': ['cybersecurity_program', 'vendor_management', 'business_continuity']
            },
            'GLBA': {
                'name': 'Gramm-Leach-Bliley Act',
                'controls': ['customer_data_protection', 'privacy_notices', 'safeguards_rule']
            }
        }
        
        self.institution_types = {
            'credit_union': {
                'typical_assets': ['core_banking', 'online_banking', 'mobile_banking', 'atm_network'],
                'high_risk_threats': ['ransomware', 'wire_fraud', 'credential_theft']
            },
            'farm_credit': {
                'typical_assets': ['loan_origination', 'agricultural_data', 'customer_portal', 'wire_transfer'],
                'high_risk_threats': ['business_email_compromise', 'ransomware', 'supply_chain_attacks']
            },
            'community_bank': {
                'typical_assets': ['core_banking', 'commercial_lending', 'treasury_management'],
                'high_risk_threats': ['ransomware', 'ddos', 'insider_threats']
            }
        }
    
    def analyze_threats(self, threat_data: List[Dict], 
                       institution_type: str = 'credit_union',
                       compliance_frameworks: List[str] = None) -> List[Dict]:
        """Analyze threats specific to financial services"""
        logger.info(f"Analyzing threats for {institution_type}...")
        
        if compliance_frameworks is None:
            compliance_frameworks = ['FFIEC', 'FCA']
        
        analyzed_threats = []
        
        for threat in threat_data:
            # Check if threat is relevant to financial services
            if not self._is_relevant_to_financial_services(threat):
                continue
            
            # Enrich with financial services context
            enriched_threat = {
                **threat,
                'financial_services_analysis': {
                    'institution_type': institution_type,
                    'affected_assets': self._identify_affected_assets(threat, institution_type),
                    'compliance_impact': self._assess_compliance_impact(threat, compliance_frameworks),
                    'business_impact': self._assess_business_impact(threat, institution_type),
                    'regulatory_reporting': self._determine_regulatory_reporting(threat),
                    'mitigation_priority': self._calculate_mitigation_priority(threat, institution_type)
                }
            }
            
            analyzed_threats.append(enriched_threat)
        
        # Sort by mitigation priority
        analyzed_threats.sort(
            key=lambda x: x['financial_services_analysis']['mitigation_priority'],
            reverse=True
        )
        
        logger.info(f"Identified {len(analyzed_threats)} relevant threats for financial services")
        return analyzed_threats
    
    def _is_relevant_to_financial_services(self, threat: Dict) -> bool:
        """Check if threat is relevant to financial services"""
        sectors = threat.get('custom_properties', {}).get('sectors', [])
        return 'financial_services' in sectors
    
    def _identify_affected_assets(self, threat: Dict, institution_type: str) -> List[str]:
        """Identify which assets are likely affected"""
        institution_assets = self.institution_types.get(institution_type, {}).get('typical_assets', [])
        
        # Map threat types to affected assets
        threat_type = threat.get('custom_properties', {}).get('threat_type', '')
        
        if threat_type == 'malware':
            return ['core_banking', 'endpoints', 'file_servers']
        elif threat_type == 'fraud':
            return ['wire_transfer', 'online_banking', 'email_systems']
        elif threat_type == 'vulnerability':
            return ['web_applications', 'network_infrastructure']
        else:
            return institution_assets[:2]  # Return top 2 assets
    
    def _assess_compliance_impact(self, threat: Dict, frameworks: List[str]) -> Dict[str, Any]:
        """Assess impact on compliance frameworks"""
        impact = {}
        
        for framework in frameworks:
            if framework in self.compliance_frameworks:
                impact[framework] = {
                    'affected': True,
                    'controls_to_review': self.compliance_frameworks[framework]['controls'],
                    'reporting_required': threat.get('custom_properties', {}).get('severity') in ['critical', 'high']
                }
        
        return impact
    
    def _assess_business_impact(self, threat: Dict, institution_type: str) -> Dict[str, Any]:
        """Assess business impact of threat"""
        severity = threat.get('custom_properties', {}).get('severity', 'medium')
        
        impact_levels = {
            'critical': {
                'operational': 'severe',
                'financial': 'high',
                'reputational': 'high',
                'estimated_downtime_hours': 24
            },
            'high': {
                'operational': 'moderate',
                'financial': 'moderate',
                'reputational': 'moderate',
                'estimated_downtime_hours': 8
            },
            'medium': {
                'operational': 'low',
                'financial': 'low',
                'reputational': 'low',
                'estimated_downtime_hours': 2
            }
        }
        
        return impact_levels.get(severity, impact_levels['medium'])
    
    def _determine_regulatory_reporting(self, threat: Dict) -> Dict[str, Any]:
        """Determine regulatory reporting requirements"""
        severity = threat.get('custom_properties', {}).get('severity', 'medium')
        
        reporting = {
            'required': severity in ['critical', 'high'],
            'agencies': [],
            'timeframe_hours': 72
        }
        
        if severity == 'critical':
            reporting['agencies'] = ['NCUA', 'FCA', 'FinCEN', 'FBI']
            reporting['timeframe_hours'] = 24
        elif severity == 'high':
            reporting['agencies'] = ['NCUA', 'FCA']
            reporting['timeframe_hours'] = 72
        
        return reporting
    
    def _calculate_mitigation_priority(self, threat: Dict, institution_type: str) -> int:
        """Calculate mitigation priority score (0-100)"""
        base_score = threat.get('analysis', {}).get('risk_score', 50)
        
        # Adjust based on institution-specific factors
        threat_type = threat.get('custom_properties', {}).get('threat_type', '')
        high_risk_threats = self.institution_types.get(institution_type, {}).get('high_risk_threats', [])
        
        if threat_type in high_risk_threats:
            base_score *= 1.2
        
        return min(int(base_score), 100)
    
    def generate_compliance_report(self, threats: List[Dict]) -> Dict[str, Any]:
        """Generate compliance-focused report"""
        report = {
            'generated_at': datetime.now().isoformat(),
            'total_threats': len(threats),
            'compliance_summary': {},
            'high_priority_items': []
        }
        
        # Summarize compliance impacts
        for framework in ['FFIEC', 'FCA', 'GLBA']:
            affected_threats = [
                t for t in threats 
                if framework in t.get('financial_services_analysis', {}).get('compliance_impact', {})
            ]
            report['compliance_summary'][framework] = {
                'affected_threats': len(affected_threats),
                'requires_action': len([t for t in affected_threats 
                                       if t['financial_services_analysis']['compliance_impact'][framework].get('reporting_required')])
            }
        
        # Identify high-priority items
        for threat in threats[:5]:  # Top 5
            report['high_priority_items'].append({
                'name': threat['name'],
                'priority': threat['financial_services_analysis']['mitigation_priority'],
                'affected_assets': threat['financial_services_analysis']['affected_assets'],
                'regulatory_reporting': threat['financial_services_analysis']['regulatory_reporting']
            })
        
        return report


class AgricultureAnalyzer:
    """Specialized threat analyzer for agriculture sector"""
    
    def __init__(self):
        """Initialize agriculture analyzer"""
        self.focus_areas = {
            'supply_chain': {
                'assets': ['logistics_systems', 'inventory_management', 'supplier_portals'],
                'threats': ['supply_chain_attacks', 'data_manipulation', 'third_party_compromise']
            },
            'iot_devices': {
                'assets': ['farm_sensors', 'automated_equipment', 'monitoring_systems'],
                'threats': ['device_compromise', 'botnet_recruitment', 'data_theft']
            },
            'rural_infrastructure': {
                'assets': ['satellite_communications', 'rural_broadband', 'mobile_systems'],
                'threats': ['connectivity_disruption', 'man_in_the_middle', 'signal_jamming']
            }
        }
    
    def analyze_threats(self, threat_data: List[Dict], 
                       focus_areas: List[str] = None) -> List[Dict]:
        """Analyze threats specific to agriculture sector"""
        logger.info("Analyzing threats for agriculture sector...")
        
        if focus_areas is None:
            focus_areas = ['supply_chain', 'iot_devices']
        
        analyzed_threats = []
        
        for threat in threat_data:
            # Check if threat is relevant to agriculture
            if not self._is_relevant_to_agriculture(threat):
                continue
            
            # Enrich with agriculture context
            enriched_threat = {
                **threat,
                'agriculture_analysis': {
                    'affected_areas': self._identify_affected_areas(threat, focus_areas),
                    'supply_chain_impact': self._assess_supply_chain_impact(threat),
                    'iot_vulnerability': self._assess_iot_vulnerability(threat),
                    'rural_considerations': self._assess_rural_considerations(threat),
                    'mitigation_challenges': self._identify_mitigation_challenges(threat)
                }
            }
            
            analyzed_threats.append(enriched_threat)
        
        logger.info(f"Identified {len(analyzed_threats)} relevant threats for agriculture")
        return analyzed_threats
    
    def _is_relevant_to_agriculture(self, threat: Dict) -> bool:
        """Check if threat is relevant to agriculture"""
        sectors = threat.get('custom_properties', {}).get('sectors', [])
        return 'agriculture' in sectors
    
    def _identify_affected_areas(self, threat: Dict, focus_areas: List[str]) -> List[str]:
        """Identify which agriculture areas are affected"""
        affected = []
        
        description = threat.get('description', '').lower()
        
        for area in focus_areas:
            area_info = self.focus_areas.get(area, {})
            area_threats = area_info.get('threats', [])
            
            # Check if threat matches area-specific threats
            if any(t in description for t in area_threats):
                affected.append(area)
        
        return affected if affected else focus_areas[:1]
    
    def _assess_supply_chain_impact(self, threat: Dict) -> Dict[str, Any]:
        """Assess impact on agricultural supply chain"""
        return {
            'severity': 'high' if 'supply chain' in threat.get('description', '').lower() else 'medium',
            'affected_stages': ['production', 'processing', 'distribution'],
            'food_safety_risk': threat.get('custom_properties', {}).get('severity') == 'critical'
        }
    
    def _assess_iot_vulnerability(self, threat: Dict) -> Dict[str, Any]:
        """Assess IoT device vulnerability"""
        description = threat.get('description', '').lower()
        
        return {
            'iot_relevant': 'iot' in description or 'sensor' in description,
            'device_types_at_risk': ['sensors', 'automated_equipment', 'monitoring_systems'],
            'patching_difficulty': 'high'  # IoT devices often difficult to patch
        }
    
    def _assess_rural_considerations(self, threat: Dict) -> Dict[str, Any]:
        """Assess rural-specific considerations"""
        return {
            'limited_connectivity': True,
            'remote_locations': True,
            'limited_it_resources': True,
            'response_challenges': ['geographic_dispersion', 'limited_bandwidth', 'staff_availability']
        }
    
    def _identify_mitigation_challenges(self, threat: Dict) -> List[str]:
        """Identify agriculture-specific mitigation challenges"""
        challenges = [
            'Limited IT staff in rural areas',
            'Difficulty patching IoT devices in the field',
            'Seasonal operational constraints',
            'Legacy equipment compatibility'
        ]
        
        if 'iot' in threat.get('description', '').lower():
            challenges.append('IoT device lifecycle management')
        
        return challenges
    
    def filter_iot_threats(self, threats: List[Dict]) -> List[Dict]:
        """Filter threats specifically affecting IoT devices"""
        return [
            t for t in threats 
            if t.get('agriculture_analysis', {}).get('iot_vulnerability', {}).get('iot_relevant', False)
        ]


def main():
    """Main execution function"""
    import json
    
    # Load analyzed threats
    try:
        with open('data/analyzed_threats.json', 'r') as f:
            threats = json.load(f)
    except FileNotFoundError:
        logger.error("No analyzed threats found. Run threat_analyzer.py first.")
        return
    
    # Financial Services Analysis
    print("\n" + "="*60)
    print("Financial Services Sector Analysis")
    print("="*60)
    
    fs_analyzer = FinancialServicesAnalyzer()
    fs_threats = fs_analyzer.analyze_threats(
        threats,
        institution_type='credit_union',
        compliance_frameworks=['FFIEC', 'FCA']
    )
    
    print(f"Relevant Threats: {len(fs_threats)}")
    
    if fs_threats:
        compliance_report = fs_analyzer.generate_compliance_report(fs_threats)
        print("\nCompliance Summary:")
        for framework, data in compliance_report['compliance_summary'].items():
            print(f"  {framework}: {data['affected_threats']} threats, {data['requires_action']} require action")
    
    # Agriculture Analysis
    print("\n" + "="*60)
    print("Agriculture Sector Analysis")
    print("="*60)
    
    ag_analyzer = AgricultureAnalyzer()
    ag_threats = ag_analyzer.analyze_threats(
        threats,
        focus_areas=['supply_chain', 'iot_devices', 'rural_infrastructure']
    )
    
    print(f"Relevant Threats: {len(ag_threats)}")
    
    iot_threats = ag_analyzer.filter_iot_threats(ag_threats)
    print(f"IoT-Specific Threats: {len(iot_threats)}")
    
    print("="*60 + "\n")


if __name__ == '__main__':
    main()
