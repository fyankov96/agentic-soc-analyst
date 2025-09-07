# 🕵️ Agentic SOC Analyst

An AI-powered cybersecurity threat hunting assistant that integrates with **Azure Sentinel** and **VirusTotal** to provide comprehensive security analysis. The tool pulls data directly from your **Azure Log Analytics Workspace** and enriches findings with threat intelligence.

## 🚀 Features

- **AI-Powered Threat Detection**: Leverages GPT models for intelligent threat analysis
- **Azure Sentinel Integration**: Direct connection to your Log Analytics Workspace
- **VirusTotal Integration**: Automatic IOC reputation checking and threat intelligence
- **MITRE ATT&CK Integration**: Built-in knowledge of tactics, techniques, and procedures
- **Multi-Model Support**: Choose from 2 optimized AI models based on complexity and budget
- **Comprehensive Analysis**: MDE telemetry, user sign-ins, Azure Network Security Groups telemetry, and Sentinel incidents

## 🔗 Integrations

### **Azure Log Analytics Workspace - Supported Tables:**

#### **Microsoft Defender for Endpoint (MDE)**
- **DeviceProcessEvents**
- **DeviceNetworkEvents**
- **DeviceLogonEvents**
- **DeviceFileEvents**
- **DeviceRegistryEvents**
- **AlertInfo**
- **AlertEvidence**

#### **EntraID & Activity**
- SigninLogs 
- AzureActivity

#### **Azure Network & Security**
- **AzureNetworkAnalytics_CL**

#### **Azure Sentinel**
- SecurityIncident
