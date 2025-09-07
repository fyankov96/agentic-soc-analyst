import requests
import json
from colorama import Fore, Style, init
from protocols.virustotal_scanner import VirusTotalScanner


def display_threats(threat_list):
    # Extract all IOCs from threats
    all_iocs = []
    for threat in threat_list:
        iocs = threat.get('indicators_of_compromise', [])
        all_iocs.extend(iocs)
    
    # Remove duplicates
    unique_iocs = list(set(all_iocs))
    
    # Display threat results first
    for i, threat in enumerate(threat_list, start=1):
        print(f"\n=============== Potential Threat #{i} ===============\n")
        print(f"{Fore.LIGHTCYAN_EX}Title: {threat.get('title')}{Fore.RESET}\n")
        print(f"Description: {threat.get('description')}\n")

        init(autoreset=True)

        confidence = threat.get('confidence', '').lower()
        if confidence == 'high':
            color = Fore.LIGHTRED_EX
        elif confidence == 'medium':
            color = Fore.LIGHTYELLOW_EX
        elif confidence == 'low':
            color = Fore.LIGHTBLUE_EX
        else:
            color = Style.RESET_ALL

        print(f"{color}Confidence Level: {threat.get('confidence')}")
        print("\nMITRE ATT&CK Info:")
        mitre = threat.get('mitre', {})
        print(f"  Tactic: {mitre.get('tactic')}")
        print(f"  Technique: {mitre.get('technique')}")
        print(f"  Sub-technique: {mitre.get('sub_technique')}")
        print(f"  ID: {mitre.get('id')}")
        print(f"  Description: {mitre.get('description')}")

        print("\nLog Lines:")
        for log in threat.get('log_lines', []):
            print(f"  - {log}")

        print("\nIndicators of Compromise:")
        for ioc in threat.get('indicators_of_compromise', []):
            print(f"  - {ioc}")

        print("\nTags:")
        for tag in threat.get('tags', []):
            print(f"  - {tag}")

        print("\nRecommendations:")
        for rec in threat.get('recommendations', []):
            print(f"  - {rec}")

        print(f"\nNotes: {threat.get('notes')}")
        print("=" * 51)
        print("\n")
    
    # Scan IOCs with VirusTotal if any found
    if unique_iocs:
        print(f"{Fore.LIGHTGREEN_EX}Scanning {len(unique_iocs)} unique IOCs with VirusTotal...")
        
        from protocols.virustotal_scanner import VirusTotalScanner
        scanner = VirusTotalScanner()
        vt_results = scanner.scan_multiple_iocs(unique_iocs)
        display_virustotal_results(vt_results)
    
    append_threats_to_jsonl(threat_list=threat_list)

def append_threats_to_jsonl(threat_list, filename="threats.jsonl"):
    with open(filename, "a", encoding="utf-8") as f:
        for threat in threat_list:
            json_line = json.dumps(threat, ensure_ascii=False)
            f.write(json_line + "\n")

def display_virustotal_results(vt_results: list[dict[str, any]]):
    """Display VirusTotal scan results with cache indicators"""
    print(f"\n{Fore.LIGHTCYAN_EX}=============== VirusTotal Scan Results ==============={Fore.RESET}\n")
    
    for result in vt_results:
        ioc = result.get('ioc', 'Unknown')
        ioc_type = result.get('type', 'Unknown')
        is_cached = result.get('cache_hit', False)
        
        cache_indicator = f" {Fore.LIGHTBLUE_EX}[CACHED]{Fore.RESET}" if is_cached else ""
        
        print(f"{Fore.WHITE}IOC: {ioc}{cache_indicator}")
        print(f"Type: {ioc_type.title()}")
        
        if 'error' in result:
            print(f"{Fore.LIGHTRED_EX}Error: {result['error']}{Fore.RESET}")
        elif result.get('status') == 'not_found':
            print(f"{Fore.LIGHTYELLOW_EX}Status: Not found in VirusTotal{Fore.RESET}")
        else:
            malicious = result.get('malicious', 0)
            suspicious = result.get('suspicious', 0)
            clean = result.get('clean', 0)
            total = result.get('total_engines', 0)
            
            if malicious > 0:
                color = Fore.LIGHTRED_EX
                status = "MALICIOUS"
            elif suspicious > 0:
                color = Fore.LIGHTYELLOW_EX
                status = "SUSPICIOUS"
            else:
                color = Fore.LIGHTGREEN_EX
                status = "CLEAN"
            
            print(f"{color}Detection: {status}")
            print(f"{Fore.WHITE}Engines: {malicious} malicious, {suspicious} suspicious, {clean} clean ({total} total)")
            
            if 'reputation' in result:
                rep = result['reputation']
                rep_color = Fore.LIGHTGREEN_EX if rep >= 0 else Fore.LIGHTRED_EX
                print(f"{rep_color}Reputation: {rep}")
            
            # Type-specific info
            if ioc_type == "file" and 'file_type' in result:
                print(f"{Fore.WHITE}File Type: {result['file_type']}")
                if 'names' in result and result['names']:
                    print(f"Known Names: {', '.join(result['names'])}")
            
            elif ioc_type in ["domain", "ip_address"]:
                if 'country' in result:
                    print(f"{Fore.WHITE}Country: {result['country']}")
                if 'asn' in result:
                    print(f"ASN: {result['asn']}")
        
        print("-" * 50)



tools = [
    {
        "type": "function",
        "function": {
            "name": "query_log_analytics_individual_device",
            "description": (
                "Query a Log Analytics table using KQL. "
                "Available tables include:\n"
                "- DeviceProcessEvents: Process creation and command-line info\n"
                "- DeviceNetworkEvents: Network connections\n"
                "- DeviceLogonEvents: Logon activity\n"
                "- AlertInfo: Alert metadata\n"
                "- AlertEvidence: Alert-related details\n"
                "- DeviceFileEvents: File operations\n"
                "- DeviceRegistryEvents: Registry modifications"

                "Fields (array/list) to include for the selected table:\n"
                "- DeviceProcessEvents Fields: TimeGenerated, AccountDomain, AccountName, ActionType, DeviceName, FileName, InitiatingProcessCommandLine, ProcessCommandLine\n"
                "- DeviceLogonEvents Fields: TimeGenerated, AccountName, DeviceName, ActionType, RemoteIP, RemoteDeviceName\n"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "table_name": {
                        "type": "string",
                        "description": "MDE table name (e.g. DeviceProcessEvents)"
                    },
                    "device_name": {
                        "type": "string",
                        "description": "The DeviceName to filter by (e.g., \"userpc-1\"",
                    },
                    "time_range_hours": {
                        "type": "integer",
                        "description": "How far back to search (e.g., 24 for 1 day)"
                    },
                    "fields": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of fields to return"
                    }
                },
                "required": ["table_name", "device_name", "time_range_hours", "fields"]
            }
        }
    }
]

# System message (context for GPT)
system_prompt = {
    "role": "system",
    "content": (
        "You are a cybersecurity threat hunting assistant using Microsoft Defender for Endpoint data. "
    )
}

threat_hunt_system_prompt = {
    "role": "system",
    "content": '''
You are a world-class Threat Hunting Analyst AI, specializing in identifying malicious activity, suspicious behaviors, and adversary tradecraft across diverse log sources. You possess deep knowledge of the MITRE ATT&CK framework, including tactics, techniques, sub-techniques, and associated threat actor behaviors (TTPs).

Your responsibilities include:
- Detecting threats in raw log data (e.g., Sysmon, firewall, EDR, authentication, network flow, cloud logs, etc.)
- Mapping behaviors to relevant MITRE ATT&CK tactics and techniques
- Flagging anomalies such as lateral movement, privilege escalation, credential dumping, command and control, persistence, and data exfiltration
- Assessing confidence levels and giving clear, concise recommendations (e.g., monitor, create incident, pivot, ignore)
- Extracting and highlighting Indicators of Compromise (IOCs) like IPs, hashes, domains, filenames
- Avoiding false positives and providing justifiable reasoning for your detections

Stay objective, accurate, and focused on helping the defender gain early visibility into attacker activity. Be concise, specific, and actionable.
'''
}

# Sample user request
log_analysis_prompt = {
    "role": "user",
    "content": """
I will provide raw logs below after the heading 'RAW LOGS'

Please analyze the logs for any signs of suspicious or malicious activity, including but not limited to:

Command and control communication

Privilege escalation

Credential access

Execution of abnormal or suspicious commands

Data exfiltration attempts

Lateral movement

Any known techniques from the MITRE ATT&CK framework

Return your findings in the following JSON format, which should be an array of objects — one object per suspicious instance you detect:

———
[
  {
    "title": "Brief title describing the suspicious activity",
    "description": "Detailed explanation of why this activity is suspicious, including context from the logs",
    "mitre": {
      "tactic": "e.g., Execution",
      "technique": "e.g., T1059",
      "sub_technique": "e.g., T1059.001",
      "id": "e.g., T1059, T1059.001",
      "description": "Description of the MITRE technique/sub-technique used"
    },
    "log_lines": [
      "Relevant line(s) from the logs that triggered the suspicion"
    ],
    "confidence": "Low | Medium | High — your confidence in this being malicious or needing investigation",
    "recommendations": [
      "pivot", 
      "create incident", 
      "monitor", 
      "ignore"
    ],
    "indicators_of_compromise": [
      "Any IOCs (IP, domain, hash, filename, etc.) found in the logs"
    ],
    "tags": [
      "privilege escalation", 
      "persistence", 
      "data exfiltration", 
      "C2", 
      "credential access", 
      "unusual command", 
      "reconnaissance", 
      "malware", 
      "suspicious login"
    ],
    "notes": "Optional analyst notes or assumptions made during detection"
  }
]
———
You may return an empty array ([]) if nothing suspicious is found.

This is extremely important:
YOUR ENTIRE RESPONSE SHOULD BE IN JSON FORMAT.
DO NOT PUT ANY RANDOM TEXT BEFORE OR AFTER YOUR JSON FINDINGS
YOUR ENTIRE RESPONSE SHOULD BE IN JSON FORMAT.

RAW LOGS:
———

"""
}