from policy_sentry.analysis.expand import get_expanded_policy, expand
from policy_sentry.util.policy_files import get_actions_from_statement
import json
from collections import Counter
import os


def extract_actions(policy):
    actions = []
    if isinstance(policy, list):
        # 如果策略是一个列表（展开后的策略），直接返回
        return policy
    elif isinstance(policy, dict):
        if 'Statement' in policy:
            for statement in policy['Statement']:
                if 'Action' in statement:
                    action = statement['Action']
                    if isinstance(action, str):
                        actions.append(action)
                    elif isinstance(action, list):
                        actions.extend(action)
        else:
            # 处理可能的单个语句情况
            if 'Action' in policy:
                action = policy['Action']
                if isinstance(action, str):
                    actions.append(action)
                elif isinstance(action, list):
                    actions.extend(action)
    return actions

def list_to_dict(action_list):
    action_dict = {}
    for action in action_list:
        if action in action_dict:
            action_dict[action] += 1
        else:
            action_dict[action] = 1
    return action_dict


policy_directory = 'F:/timmyisnotfat/P-Verifier/policy_benchmark/FLAW3'
total_action_counts = Counter()

for filename in os.listdir(policy_directory):
    if filename.endswith('.json'):
        file_path = os.path.join(policy_directory, filename)
        print(f"\nProcessing file: {filename}")

        with open(file_path, 'r') as file:
            try:
                policy = json.load(file)

                expanded_policy = get_expanded_policy(policy)
                print("\nExpanded Policy:")
                print(json.dumps(expanded_policy, indent=2))

                original_actions = extract_actions(policy)
                print("\nOriginal Actions:")
                print(original_actions)

                expanded_actions = extract_actions(expanded_policy)
                #expanded_actions = list_to_dict(expanded_actions)
                print("\nExpanded Actions:")
                print(expanded_actions)

                # 使用展开后的操作进行计数
                if len(expanded_actions) > len(original_actions):
                    file_action_counts = Counter(expanded_actions)
                else:
                    file_action_counts = Counter(original_actions)
                print("\nAction Counts for this file:")
                for action, count in file_action_counts.items():
                    print(f"{action}: {count}")

                total_action_counts.update(file_action_counts)

            except json.JSONDecodeError:
                print(f"Error: {filename} is not a valid JSON file.")
            except Exception as e:
                print(f"Error processing {filename}: {str(e)}")

print("\nTotal Action Counts Across All Policies:")
for action, count in total_action_counts.most_common():
    print(f"{action}: {count}")

print(f"\nTotal 'iot:Subscribe' count: {total_action_counts['iot:Subscribe']}")
