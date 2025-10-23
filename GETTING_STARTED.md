# 🚀 Getting Started Guide

## Complete Step-by-Step Instructions

---

## 📋 **Prerequisites**

- Python 3.8 or higher
- pip (Python package manager)
- Git (optional, for updates)

---

## ⚡ **Quick Start (5 Minutes)**

### **Step 1: Navigate to Project Directory**

```bash
cd ~/critical-infrastructure-threat-intel
```

### **Step 2: Install Dependencies**

```bash
pip install -r requirements.txt
```

### **Step 3: Run the Demo**

```bash
python run_demo.py
```

### **Step 4: Generate Dashboard**

```bash
python src/dashboard.py
```

### **Step 5: View Dashboard**

Open `dashboard.html` in your web browser.

**That's it! You're done!** 🎉

---

## 📖 **Detailed Instructions**

### **Installation**

#### **1. Install Python Dependencies**

```bash
cd ~/critical-infrastructure-threat-intel
pip install -r requirements.txt
```

**What gets installed:**
- `requests` - For HTTP requests to threat feeds
- `pyyaml` - For configuration file parsing
- `python-dateutil` - For date/time handling
- `stix2` - For STIX 2.1 threat format
- `taxii2-client` - For TAXII threat feeds

#### **2. Configure (Optional)**

```bash
# Copy example configuration
cp config/config.example.yaml config/config.yaml

# Edit with your settings (optional)
nano config/config.yaml
```

**Note:** The tool works with default settings using OSINT (open-source intelligence). API keys are optional for production use.

---

## 🎯 **Running the Tool**

### **Option 1: Complete Demo (Recommended)**

```bash
python run_demo.py
```

**What this does:**
1. ✅ Collects threats from all sources
2. ✅ Analyzes threats with AI/ML
3. ✅ Calculates risk scores
4. ✅ Prioritizes threats (Critical, High, Medium, Low)
5. ✅ Filters by sector (Financial Services, Agriculture)
6. ✅ Generates compliance reports
7. ✅ Saves data to JSON files

**Expected Output:**
```
======================================================================
  CRITICAL INFRASTRUCTURE THREAT INTELLIGENCE DEMO
======================================================================

📡 STEP 1: Collecting threats from all sources...
----------------------------------------------------------------------
✅ Collected 1 threats
📊 Sources: OSINT

🤖 STEP 2: Analyzing threats with AI/ML...
----------------------------------------------------------------------
✅ Analyzed 1 threats
📊 Average Risk Score: 65.0/100
📊 Priority Distribution:
   🟠 High: 1

✅ STEP 3: No critical threats detected

🏦 STEP 4: Financial Services Sector Analysis
----------------------------------------------------------------------
✅ Identified 0 threats affecting financial services

💾 STEP 5: Saving data...
----------------------------------------------------------------------
✅ Data saved successfully

======================================================================
  SUMMARY
======================================================================
✅ Total Threats Analyzed: 1
🔴 Critical Priority: 0
🟠 High Priority: 1
🟡 Medium Priority: 0
🟢 Low Priority: 0

📁 Data saved to: data/threats.json and data/analyzed_threats.json
📊 Generate dashboard: python src/dashboard.py
======================================================================
```

### **Option 2: Step-by-Step Workflow**

```bash
# Step 1: Collect threats
python src/threat_collector.py

# Step 2: Analyze threats
python src/threat_analyzer.py

# Step 3: Sector-specific analysis
python src/sector_analyzers.py

# Step 4: Generate dashboard
python src/dashboard.py
```

### **Option 3: Basic Example**

```bash
python examples/basic_usage.py
```

---

## 📊 **Viewing the Dashboard**

### **Generate Dashboard**

```bash
python src/dashboard.py
```

**Output:**
```
============================================================
Threat Intelligence Dashboard Generated
============================================================
File: dashboard.html
Open this file in your web browser to view the dashboard
============================================================
```

### **Open Dashboard in Browser**

#### **Windows (WSL)**
```bash
explorer.exe dashboard.html
```

#### **Linux with GUI**
```bash
xdg-open dashboard.html
```

#### **Mac**
```bash
open dashboard.html
```

#### **Copy to Windows Desktop**
```bash
cp dashboard.html /mnt/c/Users/Olusequn\ Fatokun/Desktop/
# Then open from Windows desktop
```

### **What the Dashboard Shows**

- 📈 **Statistics Cards**: Total threats, critical count, average risk score
- 🎨 **Visual Design**: Professional layout with colors and charts
- 📋 **Threat List**: All threats with detailed information
- 🔍 **Filters**: Filter by priority (Critical, High, Medium, Low) or sector
- ✅ **Recommendations**: Actionable steps for each threat
- 📊 **Compliance Impact**: FFIEC, FCA, GLBA mapping

---

## 📁 **Understanding the Output**

### **Data Files Created**

After running the tool, you'll find:

```bash
data/
├── threats.json              # Raw collected threats
└── analyzed_threats.json     # Analyzed threats with risk scores
```

### **View the Data**

```bash
# View collected threats
cat data/threats.json

# View analyzed threats
cat data/analyzed_threats.json

# View just the first threat
cat data/analyzed_threats.json | head -100
```

---

## 🎯 **Common Use Cases**

### **Use Case 1: Daily Threat Monitoring**

```bash
# Run every morning
cd ~/critical-infrastructure-threat-intel
python run_demo.py
python src/dashboard.py
# Open dashboard.html to review threats
```

**Time:** 2 minutes per day

### **Use Case 2: Compliance Reporting**

```bash
# Generate compliance report for credit union
python -c "
from src.threat_collector import ThreatCollector
from src.threat_analyzer import ThreatAnalyzer
from src.sector_analyzers import FinancialServicesAnalyzer

collector = ThreatCollector()
threats = collector.collect_all()

analyzer = ThreatAnalyzer()
analyzed = analyzer.analyze(threats, sector='financial_services')

fs_analyzer = FinancialServicesAnalyzer()
fs_threats = fs_analyzer.analyze_threats(
    analyzed,
    institution_type='credit_union',
    compliance_frameworks=['FFIEC', 'NCUA']
)

report = fs_analyzer.generate_compliance_report(fs_threats)
print('FFIEC Affected Threats:', report['compliance_summary']['FFIEC']['affected_threats'])
"
```

### **Use Case 3: Critical Threat Alerts**

```bash
# Check for critical threats only
python -c "
from src.threat_collector import ThreatCollector
from src.threat_analyzer import ThreatAnalyzer

collector = ThreatCollector()
threats = collector.collect_all()

analyzer = ThreatAnalyzer()
analyzed = analyzer.analyze(threats, sector='financial_services')

critical = analyzer.get_threats_by_priority('critical')
if critical:
    print(f'⚠️  ALERT: {len(critical)} CRITICAL THREATS')
    for threat in critical:
        print(f'- {threat[\"name\"]}')
else:
    print('✅ No critical threats')
"
```

---

## 🔧 **Troubleshooting**

### **Problem: "ModuleNotFoundError: No module named 'src'"**

**Solution:**
```bash
# Make sure you're in the project directory
cd ~/critical-infrastructure-threat-intel

# Set Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# Run the script
python run_demo.py
```

### **Problem: "Config file not found"**

**Solution:** This is just a warning. The tool works with defaults.

To fix:
```bash
cp config/config.example.yaml config/config.yaml
```

### **Problem: "No threats collected"**

**Solution:** This is normal with OSINT-only mode. The tool is working correctly.

To get more threats, configure API keys in `config/config.yaml`:
```yaml
threat_feeds:
  cisa_ais:
    enabled: true
    api_key: "your-api-key"
```

### **Problem: "Dashboard shows no threats"**

**Solution:** Run the complete workflow:
```bash
python run_demo.py
python src/dashboard.py
```

---

## 📚 **Additional Documentation**

- **README.md** - Complete project documentation
- **USAGE_EXAMPLES.md** - 10 practical code examples
- **docs/installation.md** - Detailed installation guide
- **docs/sector_guides/financial_services.md** - Financial services guide
- **PROMOTION_GUIDE.md** - How to promote your repository
- **NIW_EVIDENCE_CHECKLIST.md** - Evidence collection for NIW

---

## 🎓 **Learning Path**

### **Beginner (Day 1)**
1. Run `python run_demo.py`
2. View `dashboard.html`
3. Read `README.md`

### **Intermediate (Week 1)**
1. Read `USAGE_EXAMPLES.md`
2. Try different examples
3. Configure `config.yaml`
4. Customize for your organization

### **Advanced (Week 2+)**
1. Integrate with SIEM
2. Set up automated workflows
3. Add custom threat sources
4. Contribute improvements

---

## ⚙️ **Configuration**

### **Basic Configuration (config/config.yaml)**

```yaml
# Threat Intelligence Feeds
threat_feeds:
  osint:
    enabled: true  # Free, no API key needed
  
  cisa_ais:
    enabled: false  # Requires API key
    api_key: "your-key-here"
  
  fs_isac:
    enabled: false  # Requires membership
    api_key: "your-key-here"

# Sectors to Monitor
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

# Collection Settings
collection:
  interval_hours: 1
  lookback_days: 7
```

---

## 🚀 **Automation**

### **Set Up Daily Automated Run**

#### **Linux/Mac (cron)**

```bash
# Edit crontab
crontab -e

# Add this line to run daily at 6 AM
0 6 * * * cd ~/critical-infrastructure-threat-intel && python run_demo.py >> logs/daily.log 2>&1
```

#### **Windows (Task Scheduler)**

```powershell
# Create scheduled task
schtasks /create /tn "ThreatIntelDaily" /tr "python C:\path\to\run_demo.py" /sc daily /st 06:00
```

---

## 📸 **For NIW Application**

### **Screenshots to Take**

1. **Terminal Output**
   ```bash
   python run_demo.py
   # Screenshot the output
   ```

2. **Dashboard**
   ```bash
   python src/dashboard.py
   # Open dashboard.html and screenshot
   ```

3. **Data Files**
   ```bash
   ls -lh data/
   cat data/analyzed_threats.json | head -50
   # Screenshot
   ```

4. **GitHub Repository**
   - Go to: https://github.com/segene2001/critical-infrastructure-threat-intel
   - Screenshot main page
   - Screenshot README

---

## 💡 **Tips for Success**

1. **Start Simple**: Use `run_demo.py` first
2. **Read Output**: The tool tells you what it's doing
3. **Check Data**: Look at `data/*.json` files
4. **Use Dashboard**: Visual representation helps understanding
5. **Read Docs**: Check other .md files for details

---

## 🆘 **Getting Help**

- **GitHub Issues**: https://github.com/segene2001/critical-infrastructure-threat-intel/issues
- **Documentation**: Read all .md files in project
- **Examples**: Check `examples/` directory

---

## ✅ **Quick Reference**

### **Essential Commands**

```bash
# Complete workflow
python run_demo.py && python src/dashboard.py

# Just collect threats
python src/threat_collector.py

# Just analyze threats
python src/threat_analyzer.py

# Generate dashboard
python src/dashboard.py

# View data
cat data/analyzed_threats.json

# Check what's installed
pip list | grep -E "requests|yaml|stix"
```

### **File Locations**

- **Source Code**: `src/`
- **Configuration**: `config/config.yaml`
- **Data Output**: `data/`
- **Dashboard**: `dashboard.html`
- **Examples**: `examples/`
- **Documentation**: `docs/`

---

## 🎉 **You're Ready!**

Run this now:
```bash
cd ~/critical-infrastructure-threat-intel
python run_demo.py
```

Then open `dashboard.html` in your browser!

**Welcome to Critical Infrastructure Threat Intelligence!** 🛡️

