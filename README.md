# Critical Infrastructure Threat Intelligence Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Security: Critical Infrastructure](https://img.shields.io/badge/security-critical%20infrastructure-red.svg)](https://www.cisa.gov/)

## 🎯 Overview

An AI-driven threat intelligence framework specifically designed for **critical infrastructure protection**, with focus on **Financial Services (PPD-21 Sector #6)** and **Food & Agriculture (PPD-21 Sector #2)** sectors. This framework provides automated threat detection, analysis, and response capabilities aligned with federal cybersecurity mandates.

## 🏛️ Federal Alignment

This project directly supports multiple federal cybersecurity initiatives:

### Executive Order 14028 - Improving the Nation's Cybersecurity
- ✅ Implements advanced threat detection and automated response
- ✅ Provides real-time threat intelligence for critical infrastructure
- ✅ Enables information sharing across sectors
- ✅ Supports modernization of cybersecurity defenses

### Presidential Policy Directive 21 (PPD-21) - Critical Infrastructure Security
- ✅ **Sector #6 (Financial Services):** Protects banking, credit unions, and financial institutions
- ✅ **Sector #2 (Food & Agriculture):** Secures agricultural supply chain and rural financial services
- ✅ Enables cross-sector threat intelligence sharing
- ✅ Supports public-private partnerships for infrastructure protection

### CISA National Cybersecurity Strategy
- ✅ Aligns with CISA's critical infrastructure protection mission
- ✅ Implements automated threat detection and response
- ✅ Facilitates cross-sector information sharing
- ✅ Supports CISA's Cybersecurity Performance Goals (CPGs)

### NIST Cybersecurity Framework
- ✅ **Identify:** Asset discovery and threat landscape mapping
- ✅ **Protect:** Proactive threat mitigation controls
- ✅ **Detect:** AI/ML-based anomaly and threat detection
- ✅ **Respond:** Automated incident response workflows
- ✅ **Recover:** Threat intelligence-driven recovery procedures

## 🚀 Key Features

### 1. Multi-Source Threat Intelligence Aggregation
- Integrates feeds from CISA, FBI IC3, FS-ISAC, and open-source intelligence
- Normalizes threat data into standardized STIX 2.1 format
- Automated deduplication and correlation
- Real-time threat feed updates

### 2. AI/ML-Powered Threat Analysis
- Machine learning models for threat classification and prioritization
- Behavioral analysis for advanced persistent threats (APTs)
- Anomaly detection using unsupervised learning
- Predictive threat modeling

### 3. Sector-Specific Threat Detection
- **Financial Services:** Banking trojans, wire fraud, ransomware, insider threats
- **Agriculture:** Supply chain attacks, IoT vulnerabilities, rural infrastructure threats
- Custom threat profiles for Farm Credit System institutions
- Regulatory compliance mapping (FFIEC, FCA, GLBA)

### 4. Automated Response & Integration
- SIEM integration (Splunk, QRadar, Sentinel)
- SOAR playbook automation
- Threat intelligence platform (TIP) connectors
- REST API for custom integrations

### 5. Compliance & Reporting
- FFIEC Cybersecurity Assessment Tool (CAT) alignment
- FCA examination preparation reports
- CISA reporting format compliance
- Executive dashboards and metrics

## 📋 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Threat Intelligence Sources               │
│  CISA AIS │ FBI IC3 │ FS-ISAC │ OSINT │ Commercial Feeds    │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              Data Collection & Normalization                 │
│         (STIX 2.1, TAXII, Custom Parsers)                   │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                 AI/ML Analysis Engine                        │
│  Threat Classification │ Prioritization │ Correlation        │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              Sector-Specific Processing                      │
│    Financial Services Rules │ Agriculture Rules              │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│           Response & Integration Layer                       │
│     SIEM │ SOAR │ TIP │ Ticketing │ Notifications           │
└─────────────────────────────────────────────────────────────┘
```

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager
- Access to threat intelligence feeds (API keys)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/segene2001/critical-infrastructure-threat-intel.git
cd critical-infrastructure-threat-intel

# Install dependencies
pip install -r requirements.txt

# Configure threat feeds
cp config/config.example.yaml config/config.yaml
# Edit config.yaml with your API keys and settings

# Run the threat intelligence collector
python src/threat_collector.py

# Start the analysis engine
python src/threat_analyzer.py

# Launch the dashboard
python src/dashboard.py
```

## 📖 Usage Examples

### Example 1: Collect and Analyze Threats

```python
from src.threat_collector import ThreatCollector
from src.threat_analyzer import ThreatAnalyzer

# Initialize collector
collector = ThreatCollector(config_path='config/config.yaml')

# Collect threats from all configured sources
threats = collector.collect_all()

# Analyze threats with AI/ML
analyzer = ThreatAnalyzer()
analyzed_threats = analyzer.analyze(threats, sector='financial_services')

# Get high-priority threats
critical_threats = [t for t in analyzed_threats if t.priority == 'critical']

for threat in critical_threats:
    print(f"Threat: {threat.name}")
    print(f"Sector: {threat.sector}")
    print(f"Indicators: {threat.iocs}")
    print(f"Recommended Actions: {threat.recommendations}")
```

### Example 2: Financial Services Threat Detection

```python
from src.sector_analyzers import FinancialServicesAnalyzer

# Initialize financial services analyzer
fs_analyzer = FinancialServicesAnalyzer()

# Analyze threats specific to banking/credit unions
fs_threats = fs_analyzer.analyze_threats(
    threat_data=threats,
    institution_type='credit_union',
    compliance_frameworks=['FFIEC', 'FCA', 'GLBA']
)

# Generate compliance report
report = fs_analyzer.generate_compliance_report(fs_threats)
```

### Example 3: Agriculture Sector Protection

```python
from src.sector_analyzers import AgricultureAnalyzer

# Initialize agriculture analyzer
ag_analyzer = AgricultureAnalyzer()

# Analyze threats to agricultural supply chain
ag_threats = ag_analyzer.analyze_threats(
    threat_data=threats,
    focus_areas=['supply_chain', 'iot_devices', 'rural_infrastructure']
)

# Get IoT-specific threats
iot_threats = ag_analyzer.filter_iot_threats(ag_threats)
```

### Example 4: SIEM Integration

```python
from src.integrations import SIEMIntegration

# Initialize SIEM connector
siem = SIEMIntegration(
    platform='splunk',
    host='splunk.example.com',
    api_key='your-api-key'
)

# Send threats to SIEM
for threat in critical_threats:
    siem.send_alert(threat)

# Create correlation rules
siem.create_correlation_rule(
    name='Financial Services Ransomware',
    threats=critical_threats,
    severity='high'
)
```

## 📊 Features by Component

### Threat Collector (`src/threat_collector.py`)
- Multi-source feed aggregation
- STIX 2.1 normalization
- Automated scheduling
- Rate limiting and error handling

### Threat Analyzer (`src/threat_analyzer.py`)
- ML-based threat classification
- Risk scoring algorithm
- Threat correlation engine
- False positive reduction

### Sector Analyzers (`src/sector_analyzers/`)
- Financial Services analyzer
- Agriculture analyzer
- Custom sector templates
- Compliance mapping

### Integrations (`src/integrations/`)
- SIEM connectors (Splunk, QRadar, Sentinel)
- SOAR integration (Phantom, Demisto)
- TIP integration (MISP, ThreatConnect)
- Ticketing systems (ServiceNow, Jira)

### Dashboard (`src/dashboard.py`)
- Real-time threat visualization
- Sector-specific views
- Compliance status tracking
- Executive reporting

## 🔧 Configuration

Edit `config/config.yaml` to configure:

```yaml
threat_feeds:
  cisa_ais:
    enabled: true
    api_key: "your-api-key"
    
  fs_isac:
    enabled: true
    api_key: "your-api-key"
    
sectors:
  financial_services:
    enabled: true
    institution_types:
      - credit_union
      - bank
      - farm_credit
    compliance_frameworks:
      - FFIEC
      - FCA
      - GLBA
      
  agriculture:
    enabled: true
    focus_areas:
      - supply_chain
      - iot_devices
      - rural_infrastructure

ml_models:
  threat_classification:
    model_path: "models/threat_classifier.pkl"
    confidence_threshold: 0.85
    
integrations:
  siem:
    platform: "splunk"
    host: "splunk.example.com"
    port: 8089
```

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [Configuration Guide](docs/configuration.md)
- [API Reference](docs/api_reference.md)
- [Sector-Specific Guides](docs/sector_guides/)
  - [Financial Services](docs/sector_guides/financial_services.md)
  - [Agriculture](docs/sector_guides/agriculture.md)
- [Integration Guides](docs/integrations/)
- [Compliance Mapping](docs/compliance/)

## 🎯 Use Cases

### Financial Services
- **Credit Unions:** Detect and respond to wire fraud, ransomware, and insider threats
- **Farm Credit System:** Protect agricultural lending infrastructure
- **Community Banks:** Affordable threat intelligence for smaller institutions
- **Compliance:** Automated FFIEC CAT and FCA examination preparation

### Agriculture
- **Supply Chain Security:** Detect threats to food supply chain
- **IoT Protection:** Secure agricultural IoT devices and sensors
- **Rural Infrastructure:** Protect rural financial services and connectivity
- **Regulatory Compliance:** Support USDA and FDA cybersecurity requirements

### Cross-Sector
- **Information Sharing:** Enable threat intelligence sharing between sectors
- **Incident Response:** Coordinated response to multi-sector threats
- **Trend Analysis:** Identify emerging threats affecting multiple sectors

## 🔒 Security & Privacy

- All threat data encrypted at rest and in transit
- API keys and credentials stored in secure vault
- Role-based access control (RBAC)
- Audit logging for all operations
- Compliance with data protection regulations
- No PII or sensitive data in threat feeds

## 🤝 Contributing

Contributions are welcome! This project supports critical infrastructure protection.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Create a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **CISA** for critical infrastructure protection guidance
- **FS-ISAC** for financial services threat intelligence
- **NIST** for cybersecurity frameworks and standards
- **Farm Credit Administration** for agricultural financial sector guidance
- Open-source security community

## 📞 Contact & Support

- **Author:** Oluwasegun Fatokun
- **GitHub:** [@segene2001](https://github.com/segene2001)
- **Project Link:** [https://github.com/segene2001/critical-infrastructure-threat-intel](https://github.com/segene2001/critical-infrastructure-threat-intel)

## 🎖️ Federal Compliance Statement

This framework is designed to support compliance with:
- Executive Order 14028 (Improving the Nation's Cybersecurity)
- Presidential Policy Directive 21 (Critical Infrastructure Security)
- CISA Cybersecurity Performance Goals (CPGs)
- NIST Cybersecurity Framework
- FFIEC Cybersecurity Assessment Tool
- Farm Credit Administration cybersecurity requirements

---

**Protecting America's Critical Infrastructure Through Advanced Threat Intelligence**
