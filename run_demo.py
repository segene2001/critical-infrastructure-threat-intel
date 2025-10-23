#!/usr/bin/env python3
"""
Simple Demo Script - Run from project root directory
Demonstrates threat collection and analysis
"""

import sys
import os

# Ensure we can import from src
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.threat_collector import ThreatCollector
from src.threat_analyzer import ThreatAnalyzer
from src.sector_analyzers import FinancialServicesAnalyzer


def main():
    print("\n" + "="*70)
    print("  CRITICAL INFRASTRUCTURE THREAT INTELLIGENCE DEMO")
    print("="*70)
    
    # Step 1: Collect Threats
    print("\n📡 STEP 1: Collecting threats from all sources...")
    print("-"*70)
    collector = ThreatCollector()
    threats = collector.collect_all()
    print(f"✅ Collected {len(threats)} threats")
    
    # Show threat sources
    sources = set(t.get('external_references', [{}])[0].get('source_name', 'unknown') for t in threats)
    print(f"📊 Sources: {', '.join(sources)}")
    
    # Step 2: Analyze Threats
    print("\n🤖 STEP 2: Analyzing threats with AI/ML...")
    print("-"*70)
    analyzer = ThreatAnalyzer()
    analyzed_threats = analyzer.analyze(threats, sector='financial_services')
    print(f"✅ Analyzed {len(analyzed_threats)} threats")
    
    # Show priority distribution
    summary = analyzer.generate_summary_report()
    print(f"📊 Average Risk Score: {summary['average_risk_score']}/100")
    print(f"📊 Priority Distribution:")
    for priority, count in summary['priority_distribution'].items():
        emoji = "🔴" if priority == "critical" else "🟠" if priority == "high" else "🟡" if priority == "medium" else "🟢"
        print(f"   {emoji} {priority.capitalize()}: {count}")
    
    # Step 3: Show Critical Threats
    critical_threats = analyzer.get_threats_by_priority('critical')
    if critical_threats:
        print("\n⚠️  STEP 3: CRITICAL THREATS DETECTED")
        print("-"*70)
        for i, threat in enumerate(critical_threats, 1):
            print(f"\n{i}. {threat['name']}")
            print(f"   🎯 Risk Score: {threat['analysis']['risk_score']}/100")
            print(f"   🏢 Sectors: {', '.join(threat.get('custom_properties', {}).get('sectors', []))}")
            print(f"   ⚡ Priority: {threat['analysis']['priority'].upper()}")
            print(f"\n   📋 TOP 3 RECOMMENDATIONS:")
            for j, rec in enumerate(threat['analysis']['recommendations'][:3], 1):
                print(f"      {j}. {rec}")
    else:
        print("\n✅ STEP 3: No critical threats detected")
    
    # Step 4: Financial Services Analysis
    print("\n🏦 STEP 4: Financial Services Sector Analysis")
    print("-"*70)
    fs_analyzer = FinancialServicesAnalyzer()
    fs_threats = fs_analyzer.analyze_threats(
        analyzed_threats,
        institution_type='credit_union',
        compliance_frameworks=['FFIEC', 'FCA']
    )
    print(f"✅ Identified {len(fs_threats)} threats affecting financial services")
    
    if fs_threats:
        compliance_report = fs_analyzer.generate_compliance_report(fs_threats)
        print(f"\n📊 COMPLIANCE IMPACT:")
        for framework, data in compliance_report['compliance_summary'].items():
            print(f"   {framework}:")
            print(f"      • Affected Threats: {data['affected_threats']}")
            print(f"      • Requires Action: {data['requires_action']}")
    
    # Step 5: Summary
    print("\n" + "="*70)
    print("  SUMMARY")
    print("="*70)
    print(f"✅ Total Threats Analyzed: {len(analyzed_threats)}")
    print(f"🔴 Critical Priority: {len(analyzer.get_threats_by_priority('critical'))}")
    print(f"🟠 High Priority: {len(analyzer.get_threats_by_priority('high'))}")
    print(f"🟡 Medium Priority: {len(analyzer.get_threats_by_priority('medium'))}")
    print(f"🟢 Low Priority: {len(analyzer.get_threats_by_priority('low'))}")
    print(f"\n📁 Data saved to: data/threats.json and data/analyzed_threats.json")
    print(f"📊 Generate dashboard: python src/dashboard.py")
    print("="*70 + "\n")


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\nMake sure you're running from the project root directory:")
        print("  cd ~/critical-infrastructure-threat-intel")
        print("  python run_demo.py")
        sys.exit(1)

