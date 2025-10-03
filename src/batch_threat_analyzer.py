#!/usr/bin/env python3
"""
Advanced Batch Threat Analyzer
Process multiple IOCs with relationship mapping and campaign detection
"""

import json
import time
import argparse
import sys
from datetime import datetime
from typing import List, Dict, Any
from VC_ioc_Lookup import EnhancedVirusTotalClient, ThreatIntelligenceAnalyzer

class AdvancedBatchProcessor:
    def __init__(self, api_key: str):
        self.vt_client = EnhancedVirusTotalClient(api_key)
        self.analyzer = ThreatIntelligenceAnalyzer()
        self.results = []
        self.campaigns = {}
        self.relationships = {}
    
    def process_ioc_file(self, input_file: str, output_file: str, delay: int = 15):
        """Process IOCs from file with advanced analysis"""
        print("🚀 Starting Advanced Batch Threat Analysis...")
        
        iocs = self._read_and_classify_iocs(input_file)
        total_iocs = len(iocs)
        
        print(f"📁 Loaded {total_iocs} IOCs for analysis")
        
        for i, (ioc_type, ioc_value) in enumerate(iocs, 1):
            print(f"\n🔍 Processing {i}/{total_iocs}: {ioc_type.upper()} - {ioc_value}")
            
            # Get VT data
            vt_data = self._lookup_ioc(ioc_type, ioc_value)
            
            if vt_data:
                # Generate threat report
                threat_report = self.analyzer.generate_threat_report(ioc_type, ioc_value, vt_data)
                self.results.append(threat_report)
                
                # Update campaign tracking
                self._update_campaign_analysis(threat_report)
                
                # Display progress
                risk_score = threat_report['summary']['risk_score']
                print(f"   Risk Score: {risk_score}/100 - {threat_report['summary']['recommendation']}")
            else:
                print(f"   ❌ No data obtained")
            
            # Rate limiting
            if i < total_iocs:  # Don't delay after last item
                print(f"   ⏳ Waiting {delay} seconds...")
                time.sleep(delay)
        
        # Final analysis
        self._perform_batch_analysis()
        
        # Save results
        self._save_advanced_report(output_file)
        
        print(f"\n✅ Analysis complete! Results saved to: {output_file}")
        self._display_batch_summary()
    
    def _read_and_classify_iocs(self, filename: str) -> List[tuple]:
        """Read and classify IOCs from file"""
        iocs = []
        try:
            with open(filename, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    ioc_type, ioc_value = self._advanced_classify_ioc(line)
                    if ioc_type:
                        iocs.append((ioc_type, ioc_value))
                    else:
                        print(f"⚠️  Warning: Could not classify IOC on line {line_num}: {line}")
            
        except FileNotFoundError:
            print(f"❌ Error: File not found - {filename}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error reading file: {e}")
            sys.exit(1)
        
        return iocs
    
    def _advanced_classify_ioc(self, ioc: str) -> tuple:
        """Advanced IOC classification with better patterns"""
        import re
        
        # IP address (IPv4)
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if re.match(ip_pattern, ioc):
            return 'ip', ioc
        
        # Domain (more comprehensive pattern)
        domain_pattern = r'^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+$'
        if re.match(domain_pattern, ioc) and len(ioc) < 255:
            return 'domain', ioc
        
        # Hash patterns
        if re.match(r'^[a-fA-F0-9]{32}$', ioc):  # MD5
            return 'file', ioc
        elif re.match(r'^[a-fA-F0-9]{40}$', ioc):  # SHA1
            return 'file', ioc
        elif re.match(r'^[a-fA-F0-9]{64}$', ioc):  # SHA256
            return 'file', ioc
        
        # URL
        if ioc.startswith(('http://', 'https://', 'ftp://', 'ftps://')):
            return 'url', ioc
        
        # Email
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(email_pattern, ioc):
            return 'email', ioc
        
        return None, ioc
    
    def _lookup_ioc(self, ioc_type: str, ioc_value: str):
        """Look up IOC based on type"""
        lookup_methods = {
            'ip': self.vt_client.lookup_ip,
            'domain': self.vt_client.lookup_domain,
            'file': self.vt_client.lookup_hash,
            'url': self.vt_client.lookup_url
        }
        
        if ioc_type in lookup_methods:
            return lookup_methods[ioc_type](ioc_value)
        return None
    
    def _update_campaign_analysis(self, threat_report: Dict):
        """Update campaign tracking and relationship mapping"""
        ioc_type = threat_report['ioc_type']
        ioc_value = threat_report['ioc_value']
        risk_score = threat_report['summary']['risk_score']
        
        # Only track medium/high risk IOCs for campaigns
        if risk_score >= 40:
            campaign_key = self._generate_campaign_key(threat_report)
            
            if campaign_key not in self.campaigns:
                self.campaigns[campaign_key] = {
                    'indicators': [],
                    'total_risk': 0,
                    'first_seen': threat_report['timestamp'],
                    'last_seen': threat_report['timestamp']
                }
            
            self.campaigns[campaign_key]['indicators'].append({
                'type': ioc_type,
                'value': ioc_value,
                'risk_score': risk_score,
                'timestamp': threat_report['timestamp']
            })
            self.campaigns[campaign_key]['total_risk'] += risk_score
            self.campaigns[campaign_key]['last_seen'] = threat_report['timestamp']
    
    def _generate_campaign_key(self, threat_report: Dict) -> str:
        """Generate campaign key based on common characteristics"""
        details = threat_report.get('detailed_analysis', {})
        
        if threat_report['ioc_type'] == 'ip':
            return f"ASN_{details.get('asn', 'UNKNOWN')}"
        elif threat_report['ioc_type'] == 'domain':
            registrar = details.get('registrar', 'UNKNOWN')
            tld = threat_report['ioc_value'].split('.')[-1]
            return f"DOMAIN_{registrar}_{tld}"
        elif threat_report['ioc_type'] == 'file':
            file_type = details.get('file_type', 'UNKNOWN')
            return f"FILE_{file_type}"
        else:
            return f"OTHER_{threat_report['ioc_type']}"
    
    def _perform_batch_analysis(self):
        """Perform comprehensive batch analysis"""
        if not self.results:
            return
        
        # Calculate overall statistics
        total_iocs = len(self.results)
        high_risk = sum(1 for r in self.results if r['summary']['risk_score'] >= 70)
        medium_risk = sum(1 for r in self.results if 40 <= r['summary']['risk_score'] < 70)
        low_risk = sum(1 for r in self.results if r['summary']['risk_score'] < 40)
        
        self.batch_summary = {
            'total_iocs_processed': total_iocs,
            'high_risk_iocs': high_risk,
            'medium_risk_iocs': medium_risk,
            'low_risk_iocs': low_risk,
            'campaigns_detected': len(self.campaigns),
            'analysis_timestamp': datetime.now().isoformat(),
            'overall_risk_level': self._calculate_overall_risk(high_risk, total_iocs)
        }
    
    def _calculate_overall_risk(self, high_risk: int, total: int) -> str:
        """Calculate overall risk level for the batch"""
        if total == 0:
            return "UNKNOWN"
        
        high_risk_percentage = (high_risk / total) * 100
        
        if high_risk_percentage >= 20:
            return "CRITICAL"
        elif high_risk_percentage >= 10:
            return "HIGH"
        elif high_risk_percentage >= 5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _save_advanced_report(self, output_file: str):
        """Save comprehensive batch analysis report"""
        report = {
            'batch_summary': self.batch_summary,
            'detailed_results': self.results,
            'campaign_analysis': self.campaigns,
            'relationships': self.relationships,
            'analysis_metadata': {
                'analyzer_version': '2.0',
                'analysis_type': 'advanced_batch',
                'total_processing_time': 'N/A'  # Could be calculated with timestamps
            }
        }
        
        try:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"❌ Error saving batch report: {e}")
    
    def _display_batch_summary(self):
        """Display batch analysis summary"""
        summary = self.batch_summary
        
        print(f"\n{'='*60}")
        print(f"📊 BATCH ANALYSIS SUMMARY")
        print(f"{'='*60}")
        print(f"📁 Total IOCs Processed: {summary['total_iocs_processed']}")
        print(f"🔴 High Risk IOCs: {summary['high_risk_iocs']}")
        print(f"🟡 Medium Risk IOCs: {summary['medium_risk_iocs']}")
        print(f"🟢 Low Risk IOCs: {summary['low_risk_iocs']}")
        print(f"🎯 Campaigns Detected: {summary['campaigns_detected']}")
        print(f"🚨 Overall Risk Level: {summary['overall_risk_level']}")
        print(f"{'='*60}")
        
        # Display campaign details
        if self.campaigns:
            print(f"\n🔍 DETECTED CAMPAIGNS:")
            for campaign_key, campaign_data in self.campaigns.items():
                indicator_count = len(campaign_data['indicators'])
                avg_risk = campaign_data['total_risk'] / indicator_count
                print(f"   {campaign_key}:")
                print(f"     - Indicators: {indicator_count}")
                print(f"     - Average Risk: {avg_risk:.1f}/100")
                print(f"     - First Seen: {campaign_data['first_seen'][:10]}")
                print(f"     - Last Seen: {campaign_data['last_seen'][:10]}")

def main():
    """Main function for batch processor"""
    parser = argparse.ArgumentParser(description="Advanced Batch Threat Analyzer")
    parser.add_argument("-i", "--input", required=True, help="Input file with IOCs")
    parser.add_argument("-o", "--output", required=True, help="Output JSON file")
    parser.add_argument("-a", "--api-key", required=True, help="VirusTotal API key")
    parser.add_argument("-d", "--delay", type=int, default=15, 
                       help="Delay between requests (seconds, default: 15)")
    
    args = parser.parse_args()
    
    # Validate delay
    if args.delay < 15:
        print("⚠️  Warning: Delay less than 15 seconds may hit rate limits")
    
    processor = AdvancedBatchProcessor(args.api_key)
    processor.process_ioc_file(args.input, args.output, args.delay)

if __name__ == "__main__":
    main()