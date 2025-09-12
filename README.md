# 🕵️ Agentic SOC Analyst

An AI-powered threat hunting assistant that integrates with **Azure Sentinel** and **VirusTotal** to provide comprehensive security analysis. The tool pulls data directly from your **Azure Log Analytics Workspace** and enriches findings with threat intelligence.

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

<img width="1551" height="810" alt="Screenshot 2025-09-12 151347" src="https://github.com/user-attachments/assets/f880f64b-f0e1-44ec-bbd8-5585090a4069" />
<img width="3047" height="1057" alt="Screenshot 2025-09-12 151432" src="https://github.com/user-attachments/assets/53b77cc6-d5e2-467a-93be-dee9f8d62f0b" />
<img width="3046" height="982" alt="Screenshot 2025-09-12 151521" src="https://github.com/user-attachments/assets/6b71fa2e-51a2-4aa4-ae42-815c1bc9764b" />
<img width="612" height="1065" alt="Screenshot 2025-09-12 151548" src="https://github.com/user-attachments/assets/47f76aa6-2b94-40cc-9f27-3f69aa9cd694" />

### **Real-World Use Cases**

#### **🚨 Incident Investigation**
> "Can you give me an update on Sentinel Incident #10860 from 2 days ago? I'd like to know its current status"

#### **👤 User Compromise Assessment**
> "I'm worried that john.smith@example.com might be compromised. Can you take a look at the past 7 days of sign-in and audit activity?"

#### **🌍 Anomaly Detection**
> "Can you check SigninLogs for the past 2 hours and tell me if we've had any failed logins coming from locations that look unusual?"


## 🙏 Special Thanks

Special thanks to **[Josh Madakor](https://github.com/joshmadakor0)** and his incredible **[Cyber Range Community](https://www.skool.com/cyber-range/about)** for inspiring this project and fostering innovation in cybersecurity education and tooling.
