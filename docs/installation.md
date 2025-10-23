# Installation Guide

## Prerequisites

- Python 3.8 or higher
- pip package manager
- Git (for cloning the repository)
- Access to threat intelligence feeds (optional, for production use)

## Quick Installation

### 1. Clone the Repository

```bash
git clone https://github.com/segene2001/critical-infrastructure-threat-intel.git
cd critical-infrastructure-threat-intel
```

### 2. Create Virtual Environment (Recommended)

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure the Application

```bash
# Copy example configuration
cp config/config.example.yaml config/config.yaml

# Edit configuration with your settings
# Use your preferred text editor
notepad config/config.yaml  # Windows
nano config/config.yaml     # Linux/Mac
```

## Configuration

### Basic Configuration

Edit `config/config.yaml` to enable/disable features:

```yaml
# Enable OSINT collection (no API key required)
threat_feeds:
  osint:
    enabled: true

# Configure sectors
sectors:
  financial_services:
    enabled: true
  agriculture:
    enabled: true
```

### Advanced Configuration

For production use with commercial threat feeds:

1. **CISA AIS Access**: Apply for access at https://www.cisa.gov/ais
2. **FS-ISAC Membership**: Join at https://www.fsisac.com/
3. **Update config.yaml** with your API keys

## Verify Installation

Run the test suite to verify installation:

```bash
# Collect sample threats
python src/threat_collector.py

# Analyze threats
python src/threat_analyzer.py

# Generate dashboard
python src/dashboard.py
```

## Directory Structure

After installation, your directory should look like:

```
critical-infrastructure-threat-intel/
├── src/
│   ├── threat_collector.py
│   ├── threat_analyzer.py
│   ├── sector_analyzers.py
│   └── dashboard.py
├── config/
│   ├── config.example.yaml
│   └── config.yaml (your configuration)
├── data/ (created automatically)
├── docs/
├── examples/
├── tests/
├── requirements.txt
└── README.md
```

## Troubleshooting

### Common Issues

**Issue**: `ModuleNotFoundError: No module named 'yaml'`
**Solution**: Install dependencies: `pip install -r requirements.txt`

**Issue**: `FileNotFoundError: config/config.yaml`
**Solution**: Copy example config: `cp config/config.example.yaml config/config.yaml`

**Issue**: Permission denied when creating directories
**Solution**: Run with appropriate permissions or create directories manually

## Next Steps

- Read the [Configuration Guide](configuration.md)
- Review [API Reference](api_reference.md)
- Explore [Sector-Specific Guides](sector_guides/)
- Set up [Integrations](integrations/)

## Support

For issues or questions:
- GitHub Issues: https://github.com/segene2001/critical-infrastructure-threat-intel/issues
- Documentation: https://github.com/segene2001/critical-infrastructure-threat-intel/docs
