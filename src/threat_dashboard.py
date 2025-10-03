#!/usr/bin/env python3
"""
Threat Intelligence Dashboard
Visualize and analyze threat intelligence results
"""

import json
import argparse
from datetime import datetime
from typing import Dict, List
import matplotlib.pyplot as plt
import seaborn as sns

class ThreatDashboard:
    def __init__(self, report_file: str):
        self.report_file = report_file
        self.data = self._load_report()
    
    def _load_report(self) -> Dict:
        """Load threat intelligence report"""
        try:
            with open(self.report_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"❌ Error: Report file not found - {self.report_file}")
            exit(1)
        except json.JSONDecodeError:
            print(f"❌ Error: Invalid JSON in report file - {self.report_file}")
            exit(1)
    
    def display_summary(self):
        """Display comprehensive summary"""
        if 'batch_summary' in self.data:
            self._display_batch_summary()
        else:
            self._display_single_summary()
    
    def _display_batch_summary(self):
        """Display batch analysis summary"""
        summary = self.data['batch_summary']
        
        print("\n" + "="*70)
        print("🎯 THREAT INTELLIGENCE DASHBOARD - BATCH ANALYSIS")
        print("="*70)
        print(f"📅 Analysis Date: {summary.get('analysis_timestamp', 'N/A')}")
        print(f"📊 Total IOCs Analyzed: {summary['total_iocs_processed']}")
        print(f"🚨 Overall Risk Level: {summary['overall_risk_level']}")
        print("\n📈 RISK DISTRIBUTION:")
        print(f"   🔴 High Risk: {summary['high_risk_iocs']} IOCs")
        print(f"   🟡 Medium Risk: {summary['medium_risk_iocs']} IOCs") 
        print(f"   🟢 Low Risk: {summary['low_risk_iocs']} IOCs")
        print(f"   🎯 Campaigns Detected: {summary['campaigns_detected']}")
        
        # Display top high-risk IOCs
        high_risk_iocs = [r for r in self.data['detailed_results'] 
                         if r['summary']['risk_score'] >= 70]
        
        if high_risk_iocs:
            print(f"\n🚨 TOP HIGH-RISK IOCs:")
            for ioc in high_risk_iocs[:5]:  # Top 5
                print(f"   • {ioc['ioc_type'].upper()}: {ioc['ioc_value']} "
                      f"(Score: {ioc['summary']['risk_score']})")
    
    def _display_single_summary(self):
        """Display single IOC analysis summary"""
        print("\n" + "="*70)
        print("🎯 THREAT INTELLIGENCE DASHBOARD - SINGLE IOC")
        print("="*70)
        
        # Assuming single report format
        report = self.data
        print(f"🔍 IOC Type: {report.get('ioc_type', 'N/A').upper()}")
        print(f"📋 IOC Value: {report.get('ioc_value', 'N/A')}")
        print(f"📅 Analysis Date: {report.get('timestamp', 'N/A')}")
        
        summary = report.get('summary', {})
        print(f"🚨 Risk Score: {summary.get('risk_score', 'N/A')}/100")
        print(f"🎯 Confidence: {summary.get('confidence', 'N/A').upper()}")
        print(f"💡 Recommendation: {summary.get('recommendation', 'N/A')}")
        
        # Display key context indicators
        context = report.get('context_analysis', [])
        if context:
            print(f"\n🔍 KEY INDICATORS:")
            for indicator in context[:3]:  # Top 3
                print(f"   ⚠️  {indicator}")
    
    def generate_visualizations(self, output_prefix: str):
        """Generate visualization charts"""
        if 'batch_summary' in self.data:
            self._generate_batch_visualizations(output_prefix)
        else:
            print("ℹ️  Visualization currently only supported for batch reports")
    
    def _generate_batch_visualizations(self, output_prefix: str):
        """Generate visualizations for batch reports"""
        try:
            # Set style
            plt.style.use('default')
            sns.set_palette("husl")
            
            # Figure 1: Risk Distribution
            self._create_risk_distribution_chart(output_prefix)
            
            # Figure 2: IOC Type Distribution
            self._create_ioc_type_chart(output_prefix)
            
            # Figure 3: Risk Over Time (if timestamps available)
            self._create_timeline_chart(output_prefix)
            
            print(f"📊 Visualizations saved with prefix: {output_prefix}")
            
        except ImportError:
            print("❌ Visualization libraries not installed. Install with:")
            print("   pip install matplotlib seaborn")
        except Exception as e:
            print(f"❌ Error generating visualizations: {e}")
    
    def _create_risk_distribution_chart(self, output_prefix: str):
        """Create risk distribution pie chart"""
        summary = self.data['batch_summary']
        
        labels = ['High Risk', 'Medium Risk', 'Low Risk']
        sizes = [
            summary['high_risk_iocs'],
            summary['medium_risk_iocs'], 
            summary['low_risk_iocs']
        ]
        colors = ['#ff6b6b', '#ffd93d', '#6bcf7f']
        
        plt.figure(figsize=(8, 6))
        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        plt.title('IOC Risk Distribution')
        plt.savefig(f'{output_prefix}_risk_distribution.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def _create_ioc_type_chart(self, output_prefix: str):
        """Create IOC type distribution chart"""
        results = self.data['detailed_results']
        
        type_counts = {}
        for result in results:
            ioc_type = result['ioc_type']
            type_counts[ioc_type] = type_counts.get(ioc_type, 0) + 1
        
        plt.figure(figsize=(10, 6))
        plt.bar(type_counts.keys(), type_counts.values(), color='skyblue')
        plt.title('IOC Type Distribution')
        plt.xlabel('IOC Type')
        plt.ylabel('Count')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(f'{output_prefix}_ioc_types.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def _create_timeline_chart(self, output_prefix: str):
        """Create risk score timeline chart"""
        results = self.data['detailed_results']
        
        # Extract timestamps and risk scores
        timestamps = []
        risk_scores = []
        
        for result in results:
            ts = result.get('timestamp', '')
            if ts:
                try:
                    # Convert to datetime for sorting
                    dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                    timestamps.append(dt)
                    risk_scores.append(result['summary']['risk_score'])
                except:
                    continue
        
        if len(timestamps) > 1:
            # Sort by timestamp
            sorted_data = sorted(zip(timestamps, risk_scores))
            timestamps, risk_scores = zip(*sorted_data)
            
            plt.figure(figsize=(12, 6))
            plt.plot(timestamps, risk_scores, marker='o', linewidth=2, markersize=4)
            plt.title('Risk Score Timeline')
            plt.xlabel('Time')
            plt.ylabel('Risk Score')
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig(f'{output_prefix}_timeline.png', dpi=300, bbox_inches='tight')
            plt.close()

def main():
    """Main function for threat dashboard"""
    parser = argparse.ArgumentParser(description="Threat Intelligence Dashboard")
    parser.add_argument("-r", "--report", required=True, help="Threat intelligence report file")
    parser.add_argument("-v", "--visualize", action="store_true", help="Generate visualizations")
    parser.add_argument("-o", "--output-prefix", default="threat_dashboard", 
                       help="Output prefix for visualizations")
    
    args = parser.parse_args()
    
    dashboard = ThreatDashboard(args.report)
    dashboard.display_summary()
    
    if args.visualize:
        dashboard.generate_visualizations(args.output_prefix)

if __name__ == "__main__":
    main()