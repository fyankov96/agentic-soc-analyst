# 📹 1. Standard Library Imports (alphabetical)
import time

# 📹 2. Third-Party Library Imports (alphabetical)
from colorama import Fore, init
from openai import OpenAI
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient

# 📹 3. Internal/Local Imports (grouped by layer or concern)
import utilities
import queries.log_analytics_queries as queries
import models.models as models
from secrets_ import LOG_ANALYTICS_WORKSPACE_ID, API_KEY

# 📹 4. Context (prompts, prompt builder)
import context.prompts as prompts
from context.prompts import SYSTEM_PROMPT_THREAT_HUNT
from context.prompt_builder import build_threat_hunt_prompt

# 📹 5. Protocols (tools, logic)
from protocols.function_tools import tools
import protocols.hunt_protocol as hunt_protocol
import protocols.tool_routing as tool_routing

init(autoreset=True)

law_client = LogsQueryClient(credential=DefaultAzureCredential())
openai_client = OpenAI(api_key=API_KEY)

def print_banner():
    """Display the agent banner"""
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*60}")
    print(f"{Fore.LIGHTCYAN_EX}    🛡️  AGENTIC SOC ANALYST - CONTINUOUS MODE  🛡️")
    print(f"{Fore.LIGHTCYAN_EX}{'='*60}")
    print(f"{Fore.WHITE}Type 'exit', 'quit', or 'q' to stop the agent")
    print(f"{Fore.WHITE}{'='*60}\n")

def run_threat_hunt(user_message):
    """Execute a single threat hunt cycle"""
    try:
        print(f"{Fore.WHITE}\nDeciding log search parameters based on user request...\n")

        # Get log query parameters from agent
        args = tool_routing.get_log_query_from_agent(openai_client, user_message)

        caller = args.get('caller', '')
        device = args.get('device_name', '')
        incident_number = args.get('incident_number', '')
        table = args['table_name']
        time_range = args['time_range_hours']
        fields = ', '.join(map(str, args["fields"]))

        print(f"{Fore.LIGHTGREEN_EX}Log search parameters finalized:")
        print(f"{Fore.WHITE}Table Name:  {table}")
        print(f"{Fore.WHITE}Caller:      {caller}")
        print(f"{Fore.WHITE}Device Name: {device}")
        print(f"{Fore.WHITE}Incident Number: {incident_number}")
        print(f"{Fore.WHITE}Time Range:  {time_range} hour(s)")
        print(f"{Fore.WHITE}Fields:      {fields}\n")

        # Query log analytics
        law_query_results = queries.query_devicelogonevents(
            log_analytics_client=law_client,
            workspace_id=LOG_ANALYTICS_WORKSPACE_ID,
            timerange_hours=time_range,
            table_name=table,
            device_name=device,
            caller=caller,
            incident_number=incident_number,
            fields=fields)

        print(f"{Fore.LIGHTGREEN_EX}Building threat hunt prompt/instructions...\n")

        # Build threat hunt prompt
        threat_hunt_user_message = build_threat_hunt_prompt(
            user_prompt=user_message["content"],
            table_name=table,
            log_data=law_query_results
        )

        print(f"{Fore.LIGHTGREEN_EX}Initiating cognitive threat hunt against targeted logs...")

        start_time = time.time()

        # Execute threat hunt
        hunt_results = hunt_protocol.hunt(
            openai_client=openai_client,
            threat_hunt_system_message=SYSTEM_PROMPT_THREAT_HUNT,
            threat_hunt_user_message=threat_hunt_user_message,
            openai_model=models.GPT_o3
        )

        elapsed = time.time() - start_time

        print(f"{Fore.WHITE}Cognitive hunt complete. Took {elapsed:.2f} seconds and found {Fore.LIGHTRED_EX}{len(hunt_results)} {Fore.WHITE}potential threats!")
        
        # Display results immediately instead of waiting for input
        utilities.display_threats(threat_list=hunt_results)
        
        print(f"\n{Fore.LIGHTBLUE_EX}Hunt completed successfully! ✅")
        return True

    except KeyboardInterrupt:
        print(f"\n{Fore.LIGHTYELLOW_EX}Hunt interrupted by user.")
        return False
    except Exception as e:
        print(f"\n{Fore.LIGHTRED_EX}Error during hunt: {str(e)}")
        print(f"{Fore.LIGHTYELLOW_EX}You can try again with a different query.")
        return False

def get_user_input():
    """Get user input without clearing screen (for continuous mode)"""
    user_input = input(f"{Fore.LIGHTBLUE_EX}Agentic SOC Analyst at your service! What would you like to do?\n\n{Fore.RESET}").strip()
    
    # Use default if empty
    if not user_input:
        user_input = "Get all processes from computer 'matopsx92137' over the last 3 hour(s) and check if any look suspicious."
    
    return {
        "role": "user",
        "content": user_input
    }

def main():
    """Main continuous loop"""
    print_banner()
    
    while True:
        try:
            # Get user message (without screen clearing)
            user_message = get_user_input()
            
            # Check for exit commands
            if user_message["content"].lower().strip() in ['exit', 'quit', 'q']:
                print(f"\n{Fore.LIGHTGREEN_EX}Shutting down Agentic SOC Analyst... 👋")
                print("Stay safe! 🛡️")
                break
            
            # Run the threat hunt
            success = run_threat_hunt(user_message)
            
            if success:
                print(f"\n{Fore.LIGHTCYAN_EX}{'='*60}")
                print(f"{Fore.LIGHTCYAN_EX}    Ready for next hunt! 🔍")
                print(f"{Fore.LIGHTCYAN_EX}{'='*60}")
            
        except KeyboardInterrupt:
            print(f"\n\n{Fore.LIGHTYELLOW_EX}Received interrupt signal...")
            confirm = input(f"{Fore.WHITE}Are you sure you want to exit? (y/n): ").strip().lower()
            if confirm in ['y', 'yes']:
                print(f"\n{Fore.LIGHTGREEN_EX}Shutting down Agentic SOC Analyst... 👋")
                print("Stay safe! 🛡️")
                break
            else:
                print(f"{Fore.LIGHTBLUE_EX}Continuing... 🔄")
                continue
                
        except Exception as e:
            print(f"\n{Fore.LIGHTRED_EX}Unexpected error: {str(e)}")
            print(f"{Fore.LIGHTYELLOW_EX}Agent will continue running...")

if __name__ == "__main__":
    main()