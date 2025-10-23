"""
Basic Usage Example
Demonstrates basic threat collection and analysis workflow
"""

from src.threat_collector import ThreatCollector
from src.threat_analyzer import ThreatAnalyzer
from src.sector_analyzers import FinancialServicesAnalyzer, AgricultureAnalyzer


def main():
    print("="*60)
    print("Critical Infrastructure Threat Intelligence - Basic Usage")
    print("="*60)
    
    # Step 1: Collect Threats
    print("\n1. Collecting threats from all sources...")
    collector = ThreatCollector()
    threats = collector.collect_all()
    print(f"   Collected {len(threats)} threats")
    
    # Step 2: Analyze Threats
    print("\n2. Analyzing threats...")
    analyzer = ThreatAnalyzer()
    analyzed_threats = analyzer.analyze(threats, sector='financial_services')
    print(f"   Analyzed {len(analyzed_threats)} threats")
    
    # Step 3: Get Critical Threats
    print("\n3. Identifying critical threats...")
    critical_threats = analyzer.get_threats_by_priority('critical')
    print(f"   Found {len(critical_threats)} critical threats")
    
    # Step 4: Display Top Threats
    print("\n4. Top 3 Critical Threats:")
    print("-"*60)
    for i, threat in enumerate(critical_threats[:3], 1):
        print(f"\n{i}. {threat['name']}")
        print(f"   Risk Score: {threat['analysis']['risk_score']}")
        print(f"   Priority: {threat['analysis']['priority']}")
        print(f"   Sectors: {', '.join(threat.get('custom_properties', {}).get('sectors', []))}")
        print(f"   Top Recommendation: {threat['analysis']['recommendations'][0]}")
    
    # Step 5: Financial Services Analysis
    print("\n" + "="*60)
    print("Financial Services Sector Analysis")
    print("="*60)
    
    fs_analyzer = FinancialServicesAnalyzer()
    fs_threats = fs_analyzer.analyze_threats(
        analyzed_threats,
        institution_type='credit_union',
        compliance_frameworks=['FFIEC', 'FCA']
    )
    
    print(f"\nFinancial Services Threats: {len(fs_threats)}")
    
    if fs_threats:
        compliance_report = fs_analyzer.generate_compliance_report(fs_threats)
        print("\nCompliance Impact:")
        for framework, data in compliance_report['compliance_summary'].items():
            print(f"  {framework}: {data['affected_threats']} threats, "
                  f"{data['requires_action']} require action")
    
    # Step 6: Agriculture Analysis
    print("\n" + "="*60)
    print("Agriculture Sector Analysis")
    print("="*60)
    
    ag_analyzer = AgricultureAnalyzer()
    ag_threats = ag_analyzer.analyze_threats(
        analyzed_threats,
        focus_areas=['supply_chain', 'iot_devices']
    )
    
    print(f"\nAgriculture Threats: {len(ag_threats)}")
    
    iot_threats = ag_analyzer.filter_iot_threats(ag_threats)
    print(f"IoT-Specific Threats: {len(iot_threats)}")
    
    # Step 7: Generate Summary Report
    print("\n" + "="*60)
    print("Summary Report")
    print("="*60)
    
    summary = analyzer.generate_summary_report()
    print(f"\nTotal Threats: {summary['total_threats']}")
    print(f"Average Risk Score: {summary['average_risk_score']}")
    print(f"\nPriority Distribution:")
    for priority, count in summary['priority_distribution'].items():
        print(f"  {priority.capitalize()}: {count}")
    
    print("\n" + "="*60)
    print("Analysis Complete!")
    print("="*60)


if __name__ == '__main__':
    main()
