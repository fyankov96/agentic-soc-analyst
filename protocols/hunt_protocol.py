import json

def hunt(openai_client, threat_hunt_system_message, threat_hunt_user_message, openai_model):
    """
    Runs the threat hunting flow:
    1. Formats the logs into a string
    2. Selects appropriate system prompt from context
    3. Passes logs + role to model
    4. Parses and returns JSON findings
    """
    
    messages = [
        threat_hunt_system_message,
        threat_hunt_user_message
    ]

    response = openai_client.chat.completions.create(
        model = openai_model,
        messages = messages
    )

    results = json.loads(response.choices[0].message.content.replace("\n","").replace("'","").replace("`","").replace("json",""))
    
    return results