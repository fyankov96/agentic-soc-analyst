import json
from context.prompts import SYSTEM_PROMPT_TOOL_SELECTION
from models import models
from protocols.function_tools import tools

# Extract and parse the function call selected by the LLM.
# This tool call is part of OpenAI's function calling feature, where the model chooses a tool (function)
# from the provided list, and returns the arguments it wants to use to call it.
# In this case, the function selected queries log data from Microsoft Defender via Log Analytics.
#
# Docs: https://platform.openai.com/docs/guides/function-calling
def get_log_query_from_agent(openai_client, user_message):
    
    response = openai_client.chat.completions.create(
        model=models.GPT_4_1,
        messages=[SYSTEM_PROMPT_TOOL_SELECTION, user_message],
        tools=tools,
        tool_choice="auto"
    )

    function_call = response.choices[0].message.tool_calls[0]
    args = json.loads(function_call.function.arguments)

    return args  # or return function_call, args