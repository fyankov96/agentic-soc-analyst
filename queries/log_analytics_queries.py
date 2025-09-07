from datetime import timedelta
from colorama import Fore
import pandas as pd

def query_devicelogonevents(log_analytics_client, workspace_id, timerange_hours, table_name, device_name, fields, caller, incident_number):

    if table_name == "AzureNetworkAnalytics_CL":
        user_query = f'''{table_name}
| where FlowType_s == "MaliciousFlow"
| project {fields}
| order by TimeGenerated desc'''
        
    elif table_name == "AzureActivity":
        user_query = f'''{table_name}
| where Caller startswith "{caller}"
| project {fields}
| order by TimeGenerated desc'''
        
    elif table_name == "SigninLogs":
        user_query = f'''{table_name}
| where UserPrincipalName startswith "{caller}"
| project {fields}
| order by TimeGenerated desc'''

    elif table_name == "SecurityIncident":
        if incident_number:
            user_query = f'''{table_name}
| where IncidentNumber == "{incident_number}"
| project {fields}
| order by TimeGenerated desc'''
        else:
            user_query = f'''{table_name}
| project {fields}
| order by TimeGenerated desc
| take 5'''

    else:
        user_query = f'''{table_name}
| where DeviceName startswith "{device_name}"
| project {fields}
| order by TimeGenerated desc'''
        
    print(f"{Fore.LIGHTGREEN_EX}Constructed KQL Query:")
    print(f"{Fore.WHITE}{user_query}\n")

    print(f"{Fore.LIGHTGREEN_EX}Querying Log Analytics Worksapce ID: '{workspace_id}'...")

    response = log_analytics_client.query_workspace(
        workspace_id=workspace_id,
        query=user_query,
        timespan=timedelta(hours=timerange_hours)
    )

    # Extract the table
    table = response.tables[0]

    print(f"{Fore.WHITE}Log Analytics query returned {len(response.tables[0].rows)} record(s).\n")

    # Extract columns and rows using dot notation
    columns = table.columns  # Already a list of strings
    rows = table.rows        # List of row data

    df = pd.DataFrame(rows, columns=columns)
    results = df.to_csv(index=False)

    return results
