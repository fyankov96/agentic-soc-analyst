from context.prompts import THREAT_HUNT_PROMPTS

FORMATTING_INSTRUCTIONS = """
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
def build_threat_hunt_prompt(user_prompt: str, table_name: str, log_data: str) -> dict:
    

    instructions = THREAT_HUNT_PROMPTS.get(table_name, "")
    combined = (
        f"User request:\n{user_prompt}\n\n"
        f"Threat Hunt Instructions:\n{instructions}\n\n"
        f"Formatting Instructions: \n{FORMATTING_INSTRUCTIONS}\n\n"
        f"Log Data:\n{log_data}"
    )

    return {"role": "user", "content": combined}