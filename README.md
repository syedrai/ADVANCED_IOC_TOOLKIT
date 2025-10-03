# ADVANCED_IOC_TOOLKIT

# 🔍 Advanced Threat Intelligence Toolkit

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Security](https://img.shields.io/badge/Security-Threat%20Intelligence-red.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

> Enterprise-grade threat intelligence platform for IOC analysis, campaign detection, and security automation.

## 🎯 Features

- **Multi-IOC Analysis**: IPs, Domains, Files, URLs
- **Advanced Risk Scoring**: Contextual threat assessment (0-100)
- **Campaign Detection**: Automatic relationship mapping
- **Batch Processing**: Analyze thousands of IOCs efficiently
- **Visual Analytics**: Interactive dashboards and charts
- **API Integration**: VirusTotal, AlienVault OTX, Abuse.ch

## 🚀 Quick Start

```bash
# Installation
git clone https://github.com/yourusername/threat-intelligence-toolkit
cd threat-intelligence-toolkit
pip install -r requirements.txt

# Single IOC Analysis
python src/vt_enhanced_ioc_lookup.py -a YOUR_API_KEY -i 185.220.101.141

# Batch Processing
python src/batch_threat_analyzer.py -a YOUR_API_KEY -i examples/ioc_examples.txt -o report.json
