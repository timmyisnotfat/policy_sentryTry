from policy_sentry.analysis.expand import get_expanded_policy, expand
from policy_sentry.util.policy_files import get_actions_from_statement
from policy_sentry.command.write_policy import write_policy_with_template
import json
from collections import Counter
import os


def extract_deny_actions_and_resources(policy):
    deny_actions_and_resources = []
    if isinstance(policy, dict):
        statements = policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]

        for statement in statements:
            if statement.get('Effect') == 'Deny':  #
                actions = statement.get('Action', [])
                resources = statement.get('Resource', [])

                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]

                # actions = expand(actions)

                for action in actions:
                    for resource in resources:
                        if "*" in resource or "#" in resource or "+" in resource:
                            deny_actions_and_resources.append((action, resource))

    return deny_actions_and_resources
'''
def getResourceWithWildcard(policies):
    policiesWC = []
    statements = policy.get('Statement', [])
    if not isinstance(statements, list):
        statements = [statements]
    for statement in statements:
        if statement.get('Effect') == 'Deny':
            actions = statement.get('Action', [])
            resources = statement.get('Resource', [])

            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            for action in actions:
                for resource in resources:
                    policiesWC.append((action, resource))

                    # 检查资源是否包含通配符
                    if '*' in resource or '#' in resource or '+' in resource:
                        policiesWC.append({
                            'Effect': 'Deny',
                            'Action': action,
                            'Resource': resource
                        })

    return policiesWC

def getOnlyDeny(policy):
    theResult = []

    for item in policy:
        if isinstance(policy,dict):
            if item.get('Effect') == 'Deny':
                resource = item.get('Resource')
                if resource:
                    theResult.append(resource)
    return theResult
'''
policy_directory = 'F:/timmyisnotfat/P-Verifier/policy_benchmark/FLAW1'
for filename in os.listdir(policy_directory):
    if filename.endswith('.json'):
        file_path = os.path.join(policy_directory, filename)
        print(f"\nProcessing file: {filename}")

        with open(file_path, 'r') as file:
            try:
                policy = json.load(file)
                processedPolicy = extract_deny_actions_and_resources(policy)
                # print("Try out:")
                # policyWCoutput = getResourceWithWildcard(processedPolicy)

                print(json.dumps(processedPolicy,indent=2))
                # print("ENDLINE--------------------------------------------------------")
                # resourceDenied = getOnlyDeny(policyWCoutput)
                # print(json.dumps(resourceDenied,indent=2))
            except json.JSONDecodeError:
                print(f"Error: {filename} is not a valid JSON file.")
            except Exception as e:
                print(f"Error processing {filename}: {str(e)}")
