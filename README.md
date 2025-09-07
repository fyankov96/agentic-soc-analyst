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
- DeviceProcessEvents
- DeviceNetworkEvents
- DeviceLogonEvents
- DeviceFileEvents
- DeviceRegistryEvents
- AlertInfo
- AlertEvidence

#### **EntraID & Activity**
- SigninLogs 
- AzureActivity

#### **Azure Network**
- AzureNetworkAnalytics_CL

#### **Azure Sentinel**
- SecurityIncident


## 🛠️ Installation & Setup

### **Prerequisites:**
- **Python 3.8+**
- **Azure CLI**
- **Azure Log Analytics Workspace ID**
- **API Keys**: OpenAI, VirusTotal

### **Step 1: Install Python Dependencies**
```bash
git clone https://github.com/yourusername/agentic-soc-analyst.git
cd agentic-soc-analyst
pip install -r requirements.txt
```

### **Step 2: Install & Configure Azure CLI**
# Windows: Download from https://aka.ms/installazurecliwindows
# macOS: brew install azure-cli  
# Linux: curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

### **Step 2: Install & Configure Azure CLI**
Download and install Azure CLI, then authenticate with Azure using `az login`

### **Step 3: Configure API Keys**

Add OpenAI, VirusTotal API keys and Log Analytics Workspace ID within secrets_.py

### **Step 4: Run**
# Run the SOC Analyst
python main.py

## 🙏 Special Thanks

Special thanks to **[Josh Madakor](https://github.com/joshmadakor0)** and his incredible **[Cyber Range Community](https://www.skool.com/cyber-range/about)** for inspiring this project and fostering innovation in cybersecurity education and tooling.
