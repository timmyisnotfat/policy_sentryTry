import os
import json
from collections import Counter
from policy_sentry.analysis.expand import get_expanded_policy


def process_iot_policies(directory_path):
    results = {}
    flaw_number = 1
    error_number = 1
    while True:
        filename = f"FLAW{flaw_number}-Error-{error_number}.json"
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
                policy = get_expanded_policy(policy)
                results[filename] = policy

                # 计算并打印当前文件中的"iot:subscribe"操作数量
                actions = extract_actions(policy)
                iot_subscribe_count = actions.count("iot:subscribe")
                print(f"Processed: {filename}, iot:subscribe count: {iot_subscribe_count}")

            except json.JSONDecodeError:
                print(f"Error: {filename} is not a valid JSON file.")
            except Exception as e:
                print(f"Error processing {filename}: {str(e)}")
        error_number += 1
    return results

def extract_actions(item):
    if isinstance(item, dict):
        if 'Statement' in item:
            return extract_actions(item['Statement'])
        return item.get('Action', [])
    elif isinstance(item, str):
        return [item]
    elif isinstance(item, list):
        actions = []
        for subitem in item:
            actions.extend(extract_actions(subitem))
        return actions
    return []


def count_total_actions(policies):
    total_action_counter = Counter()
    for policy in policies.values():
        actions = extract_actions(policy)
        total_action_counter.update(actions)
    return total_action_counter


def save_output_to_file(policies, total_action_counts, output_file):
    with open(output_file, 'w') as f:
        for filename, policy in policies.items():
            f.write(f"\nPolicy for {filename}:\n")
            f.write(json.dumps(policy, indent=4))
            f.write("\n\n")
        f.write("\nTotal Action Counts Across All Policies:\n")
        for action, count in total_action_counts.items():
            f.write(f"{action}: {count}\n")


if __name__ == '__main__':
    policy_directory = 'F:/timmyisnotfat/P-Verifier/policy_benchmark/FLAW1'
    output_file = 'policies_output.txt'

    policies = process_iot_policies(policy_directory)

    # 打印处理的策略以进行调试
    print("Processed Policies:")
    print(json.dumps(policies, indent=2))

    total_action_counts = count_total_actions(policies)

    save_output_to_file(policies, total_action_counts, output_file)

    print(f"Output has been saved to {output_file}")
    print("\nTotal Action Counts Across All Policies:")
    for action, count in total_action_counts.items():
        print(f"{action}: {count}")
