"""
Threat Intelligence Dashboard
Simple web-based dashboard for visualizing threat intelligence
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
import urllib.parse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatDashboard:
    """Generate HTML dashboard for threat intelligence"""
    
    def __init__(self, threats_file: str = 'data/analyzed_threats.json'):
        """Initialize dashboard"""
        self.threats_file = threats_file
        self.threats = self._load_threats()
    
    def _load_threats(self):
        """Load analyzed threats from file"""
        try:
            with open(self.threats_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Threats file not found: {self.threats_file}")
            return []
    
    def generate_html(self, output_file: str = 'dashboard.html'):
        """Generate HTML dashboard"""
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Critical Infrastructure Threat Intelligence Dashboard</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        header {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }}
        
        h1 {{
            color: #667eea;
            margin-bottom: 10px;
        }}
        
        .subtitle {{
            color: #666;
            font-size: 14px;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .stat-value {{
            font-size: 36px;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .stat-label {{
            color: #666;
            font-size: 14px;
        }}
        
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        
        .threats-section {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .threat-card {{
            border-left: 4px solid #667eea;
            padding: 20px;
            margin-bottom: 20px;
            background: #f8f9fa;
            border-radius: 5px;
        }}
        
        .threat-card.critical {{
            border-left-color: #dc3545;
        }}
        
        .threat-card.high {{
            border-left-color: #fd7e14;
        }}
        
        .threat-card.medium {{
            border-left-color: #ffc107;
        }}
        
        .threat-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        
        .threat-name {{
            font-size: 18px;
            font-weight: bold;
            color: #333;
        }}
        
        .threat-priority {{
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        
        .priority-critical {{
            background: #dc3545;
            color: white;
        }}
        
        .priority-high {{
            background: #fd7e14;
            color: white;
        }}
        
        .priority-medium {{
            background: #ffc107;
            color: #333;
        }}
        
        .priority-low {{
            background: #28a745;
            color: white;
        }}
        
        .threat-description {{
            color: #666;
            margin-bottom: 15px;
            line-height: 1.6;
        }}
        
        .threat-meta {{
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            margin-bottom: 15px;
        }}
        
        .meta-item {{
            font-size: 13px;
            color: #666;
        }}
        
        .meta-label {{
            font-weight: bold;
            color: #333;
        }}
        
        .recommendations {{
            background: white;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
        }}
        
        .recommendations h4 {{
            margin-bottom: 10px;
            color: #667eea;
        }}
        
        .recommendations ul {{
            list-style-position: inside;
            color: #666;
        }}
        
        .recommendations li {{
            margin-bottom: 5px;
        }}
        
        .sector-tag {{
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 3px 10px;
            border-radius: 15px;
            font-size: 11px;
            margin-right: 5px;
        }}
        
        .filter-section {{
            margin-bottom: 20px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}
        
        .filter-btn {{
            padding: 8px 16px;
            border: 2px solid #667eea;
            background: white;
            color: #667eea;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
        }}
        
        .filter-btn.active {{
            background: #667eea;
            color: white;
        }}
        
        .timestamp {{
            text-align: center;
            color: #666;
            font-size: 12px;
            margin-top: 30px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Critical Infrastructure Threat Intelligence Dashboard</h1>
            <p class="subtitle">Real-time threat monitoring for Financial Services & Agriculture sectors</p>
        </header>
        
        <div class="stats-grid">
            {self._generate_stats_html()}
        </div>
        
        <div class="threats-section">
            <h2 style="margin-bottom: 20px;">Active Threats</h2>
            
            <div class="filter-section">
                <button class="filter-btn active" onclick="filterThreats('all')">All Threats</button>
                <button class="filter-btn" onclick="filterThreats('critical')">Critical</button>
                <button class="filter-btn" onclick="filterThreats('high')">High</button>
                <button class="filter-btn" onclick="filterThreats('financial_services')">Financial Services</button>
                <button class="filter-btn" onclick="filterThreats('agriculture')">Agriculture</button>
            </div>
            
            <div id="threats-container">
                {self._generate_threats_html()}
            </div>
        </div>
        
        <p class="timestamp">Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    </div>
    
    <script>
        function filterThreats(filter) {{
            const threats = document.querySelectorAll('.threat-card');
            const buttons = document.querySelectorAll('.filter-btn');
            
            // Update active button
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            
            // Filter threats
            threats.forEach(threat => {{
                if (filter === 'all') {{
                    threat.style.display = 'block';
                }} else if (filter === 'critical' || filter === 'high') {{
                    threat.style.display = threat.classList.contains(filter) ? 'block' : 'none';
                }} else {{
                    const sectors = threat.dataset.sectors;
                    threat.style.display = sectors.includes(filter) ? 'block' : 'none';
                }}
            }});
        }}
    </script>
</body>
</html>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        logger.info(f"Dashboard generated: {output_file}")
        return output_file
    
    def _generate_stats_html(self) -> str:
        """Generate statistics cards HTML"""
        if not self.threats:
            return ""
        
        total = len(self.threats)
        critical = len([t for t in self.threats if t.get('analysis', {}).get('priority') == 'critical'])
        high = len([t for t in self.threats if t.get('analysis', {}).get('priority') == 'high'])
        
        avg_risk = sum(t.get('analysis', {}).get('risk_score', 0) for t in self.threats) / total if total > 0 else 0
        
        return f"""
            <div class="stat-card">
                <div class="stat-value">{total}</div>
                <div class="stat-label">Total Threats</div>
            </div>
            <div class="stat-card">
                <div class="stat-value critical">{critical}</div>
                <div class="stat-label">Critical Priority</div>
            </div>
            <div class="stat-card">
                <div class="stat-value high">{high}</div>
                <div class="stat-label">High Priority</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{avg_risk:.1f}</div>
                <div class="stat-label">Average Risk Score</div>
            </div>
        """
    
    def _generate_threats_html(self) -> str:
        """Generate threats list HTML"""
        if not self.threats:
            return "<p>No threats to display</p>"
        
        html = ""
        
        for threat in self.threats[:20]:  # Show top 20 threats
            priority = threat.get('analysis', {}).get('priority', 'medium')
            risk_score = threat.get('analysis', {}).get('risk_score', 0)
            sectors = threat.get('custom_properties', {}).get('sectors', [])
            sectors_str = ','.join(sectors)
            
            recommendations = threat.get('analysis', {}).get('recommendations', [])
            recs_html = ""
            if recommendations:
                recs_html = "<div class='recommendations'><h4>Recommended Actions:</h4><ul>"
                for rec in recommendations[:5]:
                    recs_html += f"<li>{rec}</li>"
                recs_html += "</ul></div>"
            
            sectors_tags = "".join([f"<span class='sector-tag'>{s}</span>" for s in sectors])
            
            html += f"""
            <div class="threat-card {priority}" data-sectors="{sectors_str}">
                <div class="threat-header">
                    <div class="threat-name">{threat.get('name', 'Unknown Threat')}</div>
                    <div class="threat-priority priority-{priority}">{priority}</div>
                </div>
                <div class="threat-description">{threat.get('description', 'No description available')}</div>
                <div class="threat-meta">
                    <div class="meta-item">
                        <span class="meta-label">Risk Score:</span> {risk_score:.1f}
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Source:</span> {threat.get('external_references', [{}])[0].get('source_name', 'Unknown')}
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Sectors:</span> {sectors_tags}
                    </div>
                </div>
                {recs_html}
            </div>
            """
        
        return html


def main():
    """Main execution function"""
    dashboard = ThreatDashboard()
    output_file = dashboard.generate_html()
    
    print(f"\n{'='*60}")
    print(f"Threat Intelligence Dashboard Generated")
    print(f"{'='*60}")
    print(f"File: {output_file}")
    print(f"Open this file in your web browser to view the dashboard")
    print(f"{'='*60}\n")


if __name__ == '__main__':
    main()
