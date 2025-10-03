#!/usr/bin/env python3
"""
ENHANCED VirusTotal IOC Lookup Script
Advanced threat intelligence with contextual analysis, relationship mapping, and risk scoring
"""

import requests
import json
import time
import argparse
import sys
import re
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import hashlib

class EnhancedVirusTotalClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Content-Type": "application/json"
        }
        self.ioc_cache = {}  # Cache to avoid duplicate lookups
        
    def check_rate_limit(self, response):
        """Enhanced rate limiting with backoff"""
        if response.status_code == 429:
            retry_after = int(response.headers.get('Retry-After', 60))
            print(f"Rate limit exceeded. Waiting {retry_after} seconds...")
            time.sleep(retry_after)
            return True
        return False
    
    def lookup_ip(self, ip_address: str) -> Optional[Dict]:
        """Enhanced IP lookup with contextual analysis"""
        if ip_address in self.ioc_cache:
            return self.ioc_cache[ip_address]
            
        url = f"{self.base_url}/ip_addresses/{ip_address}"
        
        try:
            response = requests.get(url, headers=self.headers)
            
            if self.check_rate_limit(response):
                return self.lookup_ip(ip_address)
                
            if response.status_code == 200:
                result = response.json()
                # Add contextual analysis
                result['enhanced_analysis'] = self.analyze_ip_context(result)
                self.ioc_cache[ip_address] = result
                return result
            elif response.status_code == 404:
                print(f"IP {ip_address} not found in VirusTotal")
                return None
            else:
                print(f"Error looking up IP: {response.status_code}")
                return None
                
        except requests.RequestException as e:
            print(f"Request error: {e}")
            return None
    
    def lookup_domain(self, domain: str) -> Optional[Dict]:
        """Enhanced domain lookup with reputation analysis"""
        if domain in self.ioc_cache:
            return self.ioc_cache[domain]
            
        url = f"{self.base_url}/domains/{domain}"
        
        try:
            response = requests.get(url, headers=self.headers)
            
            if self.check_rate_limit(response):
                return self.lookup_domain(domain)
                
            if response.status_code == 200:
                result = response.json()
                # Add domain-specific analysis
                result['enhanced_analysis'] = self.analyze_domain_context(result)
                self.ioc_cache[domain] = result
                return result
            elif response.status_code == 404:
                print(f"Domain {domain} not found in VirusTotal")
                return None
            else:
                print(f"Error looking up domain: {response.status_code}")
                return None
                
        except requests.RequestException as e:
            print(f"Request error: {e}")
            return None
    
    def lookup_hash(self, file_hash: str) -> Optional[Dict]:
        """Enhanced file hash analysis with behavioral context"""
        if file_hash in self.ioc_cache:
            return self.ioc_cache[file_hash]
            
        url = f"{self.base_url}/files/{file_hash}"
        
        try:
            response = requests.get(url, headers=self.headers)
            
            if self.check_rate_limit(response):
                return self.lookup_hash(file_hash)
                
            if response.status_code == 200:
                result = response.json()
                # Add file analysis
                result['enhanced_analysis'] = self.analyze_file_context(result)
                self.ioc_cache[file_hash] = result
                return result
            elif response.status_code == 404:
                print(f"Hash {file_hash} not found in VirusTotal")
                return None
            else:
                print(f"Error looking up hash: {response.status_code}")
                return None
                
        except requests.RequestException as e:
            print(f"Request error: {e}")
            return None
    
    def lookup_url(self, url_to_check: str) -> Optional[Dict]:
        """Enhanced URL analysis with redirection tracking"""
        url_id = self._get_url_id(url_to_check)
        if not url_id:
            return None
            
        if url_id in self.ioc_cache:
            return self.ioc_cache[url_id]
            
        url = f"{self.base_url}/urls/{url_id}"
        
        try:
            response = requests.get(url, headers=self.headers)
            
            if self.check_rate_limit(response):
                return self.lookup_url(url_to_check)
                
            if response.status_code == 200:
                result = response.json()
                # Add URL analysis
                result['enhanced_analysis'] = self.analyze_url_context(result)
                self.ioc_cache[url_id] = result
                return result
            elif response.status_code == 404:
                print(f"URL {url_to_check} not found in VirusTotal")
                return None
            else:
                print(f"Error looking up URL: {response.status_code}")
                return None
                
        except requests.RequestException as e:
            print(f"Request error: {e}")
            return None
    
    def _get_url_id(self, url: str) -> Optional[str]:
        """Get URL ID for VirusTotal API"""
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return url_id
    
    def analyze_ip_context(self, vt_data: Dict) -> Dict:
        """Advanced IP context analysis"""
        attributes = vt_data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        analysis = {
            "risk_score": 0,
            "confidence": "low",
            "context_indicators": [],
            "recommendation": "Monitor",
            "shelf_life": "short"
        }
        
        # Calculate risk score (0-100)
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total = sum(stats.values())
        
        if total > 0:
            detection_ratio = (malicious + suspicious * 0.5) / total
            analysis['risk_score'] = int(detection_ratio * 100)
        
        # Contextual indicators
        country = attributes.get('country', '')
        as_owner = attributes.get('as_owner', '').lower()
        
        # High-risk indicators
        if malicious >= 10:
            analysis['context_indicators'].append("High detection count")
            analysis['confidence'] = "high"
            analysis['recommendation'] = "Block immediately"
        
        if any(indicator in as_owner for indicator in ['bulletproof', 'offshore', 'anonymous']):
            analysis['context_indicators'].append("Suspicious hosting provider")
            analysis['risk_score'] = min(analysis['risk_score'] + 20, 100)
        
        if country in ['RU', 'CN', 'KP', 'IR']:
            analysis['context_indicators'].append("High-risk country")
            analysis['risk_score'] = min(analysis['risk_score'] + 15, 100)
        
        # Reputation analysis
        reputation = attributes.get('reputation', 0)
        if reputation < -10:
            analysis['context_indicators'].append("Poor reputation score")
            analysis['risk_score'] = min(analysis['risk_score'] + 10, 100)
        
        return analysis
    
    def analyze_domain_context(self, vt_data: Dict) -> Dict:
        """Advanced domain context analysis"""
        attributes = vt_data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        analysis = {
            "risk_score": 0,
            "confidence": "low",
            "context_indicators": [],
            "recommendation": "Monitor",
            "shelf_life": "medium"
        }
        
        # Calculate risk score
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total = sum(stats.values())
        
        if total > 0:
            detection_ratio = (malicious + suspicious * 0.5) / total
            analysis['risk_score'] = int(detection_ratio * 100)
        
        # Domain age analysis
        creation_date = attributes.get('creation_date', '')
        if creation_date:
            domain_age = self.calculate_domain_age(creation_date)
            if domain_age < 30:  # Days
                analysis['context_indicators'].append(f"New domain ({domain_age} days old)")
                analysis['risk_score'] = min(analysis['risk_score'] + 25, 100)
        
        # TLD analysis
        domain = attributes.get('id', '')
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            analysis['context_indicators'].append("Suspicious TLD")
            analysis['risk_score'] = min(analysis['risk_score'] + 15, 100)
        
        # Registrar analysis
        registrar = attributes.get('registrar', '').lower()
        if any(suspicious in registrar for suspicious in ['privacy', 'anonymous', 'offshore']):
            analysis['context_indicators'].append("Privacy protection service")
            analysis['risk_score'] = min(analysis['risk_score'] + 10, 100)
        
        # Confidence adjustment
        if analysis['risk_score'] >= 70:
            analysis['confidence'] = "high"
            analysis['recommendation'] = "Block immediately"
        elif analysis['risk_score'] >= 40:
            analysis['confidence'] = "medium"
            analysis['recommendation'] = "Investigate further"
        
        return analysis
    
    def analyze_file_context(self, vt_data: Dict) -> Dict:
        """Advanced file analysis with behavioral context"""
        attributes = vt_data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        analysis = {
            "risk_score": 0,
            "confidence": "low",
            "context_indicators": [],
            "recommendation": "Monitor",
            "shelf_life": "very_short"
        }
        
        # Calculate risk score
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total = sum(stats.values())
        
        if total > 0:
            detection_ratio = (malicious + suspicious * 0.5) / total
            analysis['risk_score'] = int(detection_ratio * 100)
        
        # File type analysis
        file_type = attributes.get('type_description', '').lower()
        suspicious_types = ['executable', 'script', 'macro', 'packed']
        if any(st in file_type for st in suspicious_types):
            analysis['context_indicators'].append(f"Suspicious file type: {file_type}")
            analysis['risk_score'] = min(analysis['risk_score'] + 15, 100)
        
        # File size analysis
        size = attributes.get('size', 0)
        if size < 1000 or size > 50000000:  # Too small or too large
            analysis['context_indicators'].append(f"Suspicious file size: {size} bytes")
            analysis['risk_score'] = min(analysis['risk_score'] + 10, 100)
        
        # First seen analysis
        first_seen = attributes.get('first_submission_date', '')
        if first_seen:
            days_since_first_seen = self.calculate_days_since(first_seen)
            if days_since_first_seen < 7:
                analysis['context_indicators'].append(f"Recently first seen ({days_since_first_seen} days ago)")
                analysis['risk_score'] = min(analysis['risk_score'] + 20, 100)
        
        # Confidence adjustment
        if analysis['risk_score'] >= 60:
            analysis['confidence'] = "high"
            analysis['recommendation'] = "Block and investigate"
        elif analysis['risk_score'] >= 30:
            analysis['confidence'] = "medium"
            analysis['recommendation'] = "Investigate further"
        
        return analysis
    
    def analyze_url_context(self, vt_data: Dict) -> Dict:
        """Advanced URL context analysis"""
        attributes = vt_data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        analysis = {
            "risk_score": 0,
            "confidence": "low",
            "context_indicators": [],
            "recommendation": "Monitor",
            "shelf_life": "very_short"
        }
        
        # Calculate risk score
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total = sum(stats.values())
        
        if total > 0:
            detection_ratio = (malicious + suspicious * 0.5) / total
            analysis['risk_score'] = int(detection_ratio * 100)
        
        # URL structure analysis
        final_url = attributes.get('final_url', '')
        if final_url:
            if len(final_url) > 150:
                analysis['context_indicators'].append("Suspiciously long URL")
                analysis['risk_score'] = min(analysis['risk_score'] + 15, 100)
            
            if final_url.count('/') > 10:
                analysis['context_indicators'].append("Deep URL path structure")
                analysis['risk_score'] = min(analysis['risk_score'] + 10, 100)
        
        # Timing analysis
        first_seen = attributes.get('first_submission_date', '')
        if first_seen:
            days_since_first_seen = self.calculate_days_since(first_seen)
            if days_since_first_seen < 3:
                analysis['context_indicators'].append(f"Very recently created ({days_since_first_seen} days ago)")
                analysis['risk_score'] = min(analysis['risk_score'] + 25, 100)
        
        # Confidence adjustment
        if analysis['risk_score'] >= 70:
            analysis['confidence'] = "high"
            analysis['recommendation'] = "Block immediately"
        elif analysis['risk_score'] >= 40:
            analysis['confidence'] = "medium"
            analysis['recommendation'] = "Investigate further"
        
        return analysis
    
    def calculate_domain_age(self, creation_date: str) -> int:
        """Calculate domain age in days"""
        try:
            created = datetime.fromisoformat(creation_date.replace('Z', '+00:00'))
            now = datetime.now(created.tzinfo)
            return (now - created).days
        except:
            return 999  # Default to old if we can't parse
    
    def calculate_days_since(self, date_string: str) -> int:
        """Calculate days since given date"""
        try:
            date = datetime.fromisoformat(date_string.replace('Z', '+00:00'))
            now = datetime.now(date.tzinfo)
            return (now - date).days
        except:
            return 999

class ThreatIntelligenceAnalyzer:
    """Advanced threat intelligence analysis"""
    
    def __init__(self):
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club', '.win']
        self.high_risk_countries = ['RU', 'CN', 'KP', 'IR', 'SY', 'SD']
        self.suspicious_keywords = ['admin', 'login', 'secure', 'account', 'verify', 'update']
    
    def generate_threat_report(self, ioc_type: str, ioc_value: str, vt_data: Dict) -> Dict:
        """Generate comprehensive threat report"""
        if not vt_data:
            return {"error": "No data available"}
        
        enhanced_analysis = vt_data.get('enhanced_analysis', {})
        attributes = vt_data.get('data', {}).get('attributes', {})
        
        report = {
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "risk_score": enhanced_analysis.get('risk_score', 0),
                "confidence": enhanced_analysis.get('confidence', 'low'),
                "recommendation": enhanced_analysis.get('recommendation', 'Monitor'),
                "shelf_life": enhanced_analysis.get('shelf_life', 'unknown')
            },
            "detection_metrics": attributes.get('last_analysis_stats', {}),
            "context_analysis": enhanced_analysis.get('context_indicators', []),
            "detailed_analysis": self._get_detailed_analysis(ioc_type, attributes),
            "mitigation_recommendations": self._get_mitigation_recommendations(ioc_type, enhanced_analysis)
        }
        
        return report
    
    def _get_detailed_analysis(self, ioc_type: str, attributes: Dict) -> Dict:
        """Get detailed analysis based on IOC type"""
        analysis = {}
        
        if ioc_type == 'ip':
            analysis.update({
                "country": attributes.get('country', 'N/A'),
                "asn": attributes.get('asn', 'N/A'),
                "as_owner": attributes.get('as_owner', 'N/A'),
                "reputation": attributes.get('reputation', 'N/A'),
                "network_context": self._analyze_network_context(attributes)
            })
        elif ioc_type == 'domain':
            analysis.update({
                "creation_date": attributes.get('creation_date', 'N/A'),
                "registrar": attributes.get('registrar', 'N/A'),
                "tld_risk": self._analyze_tld_risk(attributes.get('id', '')),
                "whois_analysis": self._analyze_whois_patterns(attributes)
            })
        elif ioc_type == 'file':
            analysis.update({
                "file_type": attributes.get('type_description', 'N/A'),
                "file_size": attributes.get('size', 'N/A'),
                "first_seen": attributes.get('first_submission_date', 'N/A'),
                "last_seen": attributes.get('last_submission_date', 'N/A'),
                "behavioral_indicators": self._analyze_file_behavior(attributes)
            })
        elif ioc_type == 'url':
            analysis.update({
                "final_url": attributes.get('final_url', 'N/A'),
                "redirect_chain": attributes.get('redirect_chain', []),
                "url_structure_risk": self._analyze_url_structure(attributes.get('final_url', ''))
            })
        
        return analysis
    
    def _analyze_network_context(self, attributes: Dict) -> str:
        """Analyze network context for IP"""
        as_owner = attributes.get('as_owner', '').lower()
        country = attributes.get('country', '')
        
        if any(keyword in as_owner for keyword in ['bulletproof', 'offshore']):
            return "HIGH - Suspicious hosting provider"
        elif country in self.high_risk_countries:
            return "MEDIUM - High-risk country"
        elif 'cloud' in as_owner or 'hosting' in as_owner:
            return "LOW - Cloud hosting provider"
        else:
            return "LOW - Standard network infrastructure"
    
    def _analyze_tld_risk(self, domain: str) -> str:
        """Analyze TLD risk"""
        if any(domain.endswith(tld) for tld in self.suspicious_tlds):
            return "HIGH - Suspicious TLD"
        elif domain.endswith(('.com', '.org', '.net')):
            return "LOW - Common TLD"
        else:
            return "MEDIUM - Less common TLD"
    
    def _analyze_whois_patterns(self, attributes: Dict) -> str:
        """Analyze WHOIS patterns"""
        registrar = attributes.get('registrar', '').lower()
        creation_date = attributes.get('creation_date', '')
        
        risk_factors = []
        
        if 'privacy' in registrar or 'anonymous' in registrar:
            risk_factors.append("Privacy protection")
        
        if creation_date:
            domain_age = self._calculate_domain_age(creation_date)
            if domain_age < 30:
                risk_factors.append(f"New domain ({domain_age} days)")
        
        if risk_factors:
            return f"MEDIUM - {', '.join(risk_factors)}"
        else:
            return "LOW - Normal registration patterns"
    
    def _analyze_file_behavior(self, attributes: Dict) -> List[str]:
        """Analyze file behavioral indicators"""
        indicators = []
        file_type = attributes.get('type_description', '').lower()
        size = attributes.get('size', 0)
        
        if 'executable' in file_type and size < 10000:
            indicators.append("Small executable (possible dropper)")
        elif 'packed' in file_type or 'compressed' in file_type:
            indicators.append("Packed/compressed file")
        elif 'script' in file_type:
            indicators.append("Script file (higher risk)")
        
        return indicators
    
    def _analyze_url_structure(self, url: str) -> str:
        """Analyze URL structure risk"""
        if not url:
            return "UNKNOWN"
        
        if len(url) > 150:
            return "HIGH - Suspiciously long URL"
        elif url.count('/') > 8:
            return "MEDIUM - Deep URL path"
        elif any(keyword in url.lower() for keyword in self.suspicious_keywords):
            return "MEDIUM - Contains suspicious keywords"
        else:
            return "LOW - Normal URL structure"
    
    def _calculate_domain_age(self, creation_date: str) -> int:
        """Calculate domain age"""
        try:
            created = datetime.fromisoformat(creation_date.replace('Z', '+00:00'))
            return (datetime.now(created.tzinfo) - created).days
        except:
            return 999
    
    def _get_mitigation_recommendations(self, ioc_type: str, analysis: Dict) -> List[str]:
        """Get mitigation recommendations"""
        recommendations = []
        risk_score = analysis.get('risk_score', 0)
        
        if risk_score >= 70:
            recommendations.append(f"IMMEDIATE: Block {ioc_type.upper()} in firewall/security controls")
            recommendations.append("Investigate for compromise in environment")
            recommendations.append("Update threat intelligence feeds")
        elif risk_score >= 40:
            recommendations.append(f"MONITOR: Closely watch for {ioc_type.upper()} activity")
            recommendations.append("Consider adding to watchlist")
            recommendations.append("Review related security logs")
        else:
            recommendations.append("OBSERVE: Continue normal monitoring")
            recommendations.append("Document for future reference")
        
        # Type-specific recommendations
        if ioc_type == 'file':
            recommendations.append("Scan endpoints for file presence")
        elif ioc_type in ['ip', 'domain', 'url']:
            recommendations.append("Check network traffic logs")
            recommendations.append("Review DNS query history")
        
        return recommendations

def display_enhanced_results(ioc_type: str, ioc_value: str, threat_report: Dict):
    """Display enhanced threat intelligence results"""
    print(f"\n{'='*80}")
    print(f"🎯 ENHANCED THREAT INTELLIGENCE REPORT")
    print(f"{'='*80}")
    print(f"🔍 Type: {ioc_type.upper()}")
    print(f"📋 Value: {ioc_value}")
    print(f"🕐 Timestamp: {threat_report.get('timestamp', 'N/A')}")
    print(f"{'='*80}")
    
    summary = threat_report.get('summary', {})
    print(f"\n📊 THREAT SUMMARY:")
    print(f"   Risk Score: {summary.get('risk_score', 0)}/100")
    print(f"   Confidence: {summary.get('confidence', 'N/A').upper()}")
    print(f"   Recommendation: {summary.get('recommendation', 'N/A')}")
    print(f"   Shelf Life: {summary.get('shelf_life', 'N/A').replace('_', ' ').title()}")
    
    # Detection metrics
    metrics = threat_report.get('detection_metrics', {})
    print(f"\n🛡️ DETECTION METRICS:")
    print(f"   Malicious: {metrics.get('malicious', 0)}")
    print(f"   Suspicious: {metrics.get('suspicious', 0)}")
    print(f"   Undetected: {metrics.get('undetected', 0)}")
    print(f"   Harmless: {metrics.get('harmless', 0)}")
    print(f"   Total Engines: {sum(metrics.values())}")
    
    # Context analysis
    context = threat_report.get('context_analysis', [])
    if context:
        print(f"\n🔍 CONTEXTUAL INDICATORS:")
        for indicator in context:
            print(f"   ⚠️  {indicator}")
    
    # Detailed analysis
    detailed = threat_report.get('detailed_analysis', {})
    if detailed:
        print(f"\n📈 DETAILED ANALYSIS:")
        for key, value in detailed.items():
            if isinstance(value, list):
                print(f"   {key.replace('_', ' ').title()}:")
                for item in value:
                    print(f"     • {item}")
            else:
                print(f"   {key.replace('_', ' ').title()}: {value}")
    
    # Mitigation recommendations
    mitigations = threat_report.get('mitigation_recommendations', [])
    if mitigations:
        print(f"\n🚨 MITIGATION RECOMMENDATIONS:")
        for rec in mitigations:
            if rec.startswith('IMMEDIATE'):
                print(f"   🔴 {rec}")
            elif rec.startswith('MONITOR'):
                print(f"   🟡 {rec}")
            else:
                print(f"   🔵 {rec}")

def save_enhanced_report(output_file: str, threat_report: Dict):
    """Save enhanced threat report to file"""
    try:
        with open(output_file, 'w') as f:
            json.dump(threat_report, f, indent=2, ensure_ascii=False)
        print(f"\n💾 Enhanced threat report saved to: {output_file}")
    except Exception as e:
        print(f"❌ Error saving report: {e}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Enhanced VirusTotal IOC Lookup Tool")
    parser.add_argument("-i", "--ip", help="IP address to look up")
    parser.add_argument("-d", "--domain", help="Domain to look up")
    parser.add_argument("-f", "--file", help="File hash (MD5, SHA1, SHA256) to look up")
    parser.add_argument("-u", "--url", help="URL to look up")
    parser.add_argument("-a", "--api-key", help="VirusTotal API key", required=True)
    parser.add_argument("-o", "--output", help="Output file (JSON format)")
    
    args = parser.parse_args()
    
    # Initialize clients
    vt_client = EnhancedVirusTotalClient(args.api_key)
    analyzer = ThreatIntelligenceAnalyzer()
    
    results = None
    ioc_type = None
    ioc_value = None
    
    # Perform lookup based on IOC type
    if args.ip:
        ioc_type = 'ip'
        ioc_value = args.ip
        results = vt_client.lookup_ip(args.ip)
    elif args.domain:
        ioc_type = 'domain'
        ioc_value = args.domain
        results = vt_client.lookup_domain(args.domain)
    elif args.file:
        ioc_type = 'file'
        ioc_value = args.file
        results = vt_client.lookup_hash(args.file)
    elif args.url:
        ioc_type = 'url'
        ioc_value = args.url
        results = vt_client.lookup_url(args.url)
    else:
        print("❌ Error: Please specify an IOC to look up")
        sys.exit(1)
    
    # Generate and display threat report
    if results:
        threat_report = analyzer.generate_threat_report(ioc_type, ioc_value, results)
        display_enhanced_results(ioc_type, ioc_value, threat_report)
        
        # Save results if output file specified
        if args.output:
            save_enhanced_report(args.output, threat_report)
    else:
        print("❌ No results obtained from VirusTotal")

if __name__ == "__main__":
    main()