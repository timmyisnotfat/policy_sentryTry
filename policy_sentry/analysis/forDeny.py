import os
import json
from collections import Counter
from policy_sentry.analysis.expand import get_expanded_policy


def process_iot_policies(directory_path):
    results = {}
    deny_actions = {}
    flaw_number = 3
    error_number = 1

    while True:
        filename = f"FLAW{flaw_number}-Secure-{error_number}.json"
        file_path = os.path.join(directory_path, filename)

        if not os.path.exists(file_path):
            if error_number == 1:
                break
            else:
                flaw_number += 1
                error_number = 1
                continue

        with open(file_path, 'r') as file:
            try:
                policy = json.load(file)
                expanded_policy = get_expanded_policy(policy)
                results[filename] = expanded_policy
                deny_actions[filename] = check_for_deny_actions(policy)
                print(f"Processed: {filename}")
            except json.JSONDecodeError:
                print(f"Error: {filename} is not a valid JSON file.")
            except Exception as e:
                print(f"Error processing {filename}: {str(e)}")

        error_number += 1

    return results, deny_actions


def check_for_deny_actions(policy):
    deny_actions = []
    if isinstance(policy, dict):
        statements = policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]

        for statement in statements:
            if statement.get('Effect', '').lower() == 'deny':
                actions = extract_actions(statement)
                deny_actions.extend(actions)

    return deny_actions


def extract_actions(item):
    if isinstance(item, dict):
        action = item.get('Action', [])
        if isinstance(action, str):
            return [action]
        elif isinstance(action, list):
            return action
    return []


def count_total_actions(expanded_policies):
    total_action_counter = Counter()
    for policy in expanded_policies.values():
        actions = extract_actions(policy)
        total_action_counter.update(actions)
    return total_action_counter


def save_output_to_file(expanded_policies, total_action_counts, deny_actions, output_file):
    with open(output_file, 'w') as f:
        for filename, expanded_policy in expanded_policies.items():
            f.write(f"\nExpanded policy for {filename}:\n")
            f.write(json.dumps(expanded_policy, indent=4))
            f.write("\n\n")

        f.write("\nTotal Action Counts Across All Policies:\n")
        for action, count in total_action_counts.items():
            f.write(f"{action}: {count}\n")

        f.write("\nDeny Actions in Policies:\n")
        for filename, actions in deny_actions.items():
            if actions:
                f.write(f"{filename}: {', '.join(actions)}\n")
            else:
                f.write(f"{filename}: No deny actions\n")


if __name__ == '__main__':
    policy_directory = 'F:/timmyisnotfat/P-Verifier/policy_benchmark/FLAW3'
    output_file = 'expanded_policies_output.txt'

    expanded_policies, deny_actions = process_iot_policies(policy_directory)

    # Count total actions across all policies
    total_action_counts = count_total_actions(expanded_policies)

    # Save the output to a file
    save_output_to_file(expanded_policies, total_action_counts, deny_actions, output_file)

    print(f"Output has been saved to {output_file}")

    # Print total action counts to console
    print("\nTotal Action Counts Across All Policies:")
    for action, count in total_action_counts.items():
        print(f"{action}: {count}")

    # Print deny actions to console
    print("\nDeny Actions in Policies:")
    for filename, actions in deny_actions.items():
        if actions:
            print(f"{filename}: {', '.join(actions)}")
        else:
            print(f"{filename}: No deny actions")
