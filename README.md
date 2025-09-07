# 🕵️ Agentic SOC Analyst

An AI-powered cybersecurity threat hunting assistant that integrates with **Azure Sentinel** and **VirusTotal** to provide comprehensive security analysis. The tool pulls data directly from your **Azure Log Analytics Workspace** and enriches findings with threat intelligence.

<img width="2435" height="1150" alt="Screenshot 2025-09-07 220916" src="https://github.com/user-attachments/assets/0298dde3-e258-459a-aa3f-26eee47b6c93" />

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

#### **Entra ID & Activity**
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
git clone https://github.com/fyankov96/agentic-soc-analyst.git
cd agentic-soc-analyst
pip install -r requirements.txt
```

### **Step 2: Install & Configure Azure CLI**

**Installation:**
- **Windows:** Download from https://aka.ms/installazurecliwindows
- **macOS:** `brew install azure-cli`
- **Linux:** `curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash`

**Authentication:**
Run `az login` to authenticate with Azure

### **Step 3: Configure API Keys**

Add OpenAI, VirusTotal API keys and Log Analytics Workspace ID within `secrets_.py`

### **Step 4: Run**
```bash
# Run the SOC Analyst
python main.py
```

## 🎬 Demo & Use Case Examples

### **Watch the Demo**

https://github.com/user-attachments/assets/54e1712e-7d5f-49bc-833e-d287c20928a2

### **Real-World Use Cases**

#### **🚨 Incident Investigation**
> "Can you give me an update on Sentinel Incident #10860 from 2 days ago? I'd like to know its current status"

#### **👤 User Compromise Assessment**
> "I'm worried that john.smith@example.com might be compromised. Can you take a look at the past 7 days of sign-in and audit activity?"

#### **🌍 Anomaly Detection**
> "Can you check SigninLogs for the past 2 hours and tell me if we've had any failed logins coming from locations that look unusual?"


## 🙏 Special Thanks

Special thanks to **[Josh Madakor](https://github.com/joshmadakor0)** and his incredible **[Cyber Range Community](https://www.skool.com/cyber-range/about)** for inspiring this project and fostering innovation in cybersecurity education and tooling.
