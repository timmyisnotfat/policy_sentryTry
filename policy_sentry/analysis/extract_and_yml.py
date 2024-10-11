import json
import yaml
from policy_sentry.command.write_policy import write_policy_with_template
from policy_sentry.querying.actions import get_actions_that_support_wildcard_arns_only
from policy_sentry.querying.actions import get_actions_for_service
import re

policy = '''
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "iot:Subscribe",
            "Resource": [
                "arn:aws:iot:eu-west-1:435775406265:topicfilter/lambda/vsure/abc",
                "arn:aws:iot:eu-west-1:435775406265:topicfilter/lambda/vsure/password"
            ]
        },
        {
            "Effect": "Allow",
            "Action": "kms:Decrypt",
            "Resource": "arn:aws:kms:eu-west-1:435775406265:key/7969b24c-ad2c-4fe7-ac3a-6a14aef0f963"
        },
        {
            "Effect": "Allow",
            "Action": [
                "iot:GetV2LoggingOptions",
                "iot:DetachThingPrincipal"
            ],
            "Resource": "*"
        }
    ],
    "Expected": {
        "NotPublish": [
            "*"
        ],
        "NotReceive": [
            "*"
        ],
        "type": 0
    }
}
'''

class extract_and_output_by_yml:

    def __init__(self):
        pass

    def extract(self, policy):
        the_actions = []
        the_resources = []
        ac_re_dict = {}

        if isinstance(policy, str):
            try:
                policy = json.loads(policy)
            except json.JSONDecodeError:
                print("Error: Invalid JSON string")
                return [], [], {}

        if isinstance(policy, dict):
            statements = policy.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]

            for statement in statements:
                if statement.get('Effect') == 'Allow':
                    actions = statement.get('Action', [])
                    resources = statement.get('Resource', [])

                    # Ensure actions and resources are lists
                    if isinstance(actions, str):
                        actions = [actions]
                    if isinstance(resources, str):
                        resources = [resources]

                    # Extend the lists
                    the_actions.extend(actions)
                    the_resources.extend(resources)

                    # Update the dictionary
                    for action in actions:
                        if action not in ac_re_dict:
                            ac_re_dict[action] = set()
                        ac_re_dict[action].update(resources)

        # Remove duplicates from lists
        the_actions = list(dict.fromkeys(the_actions))
        the_resources = list(dict.fromkeys(the_resources))

        # Convert sets to lists in the dictionary
        for action in ac_re_dict:
            ac_re_dict[action] = list(ac_re_dict[action])

        return the_actions, the_resources, ac_re_dict

    def update_yml_file(self, yml_file_path, actions):
        try:
            # Read existing YAML content
            with open(yml_file_path, 'r') as file:
                yml_data = yaml.safe_load(file)

            # Update the actions in the YAML data
            if isinstance(actions, list):
                yml_data['actions'] = [f'{action}' for action in actions]
            elif isinstance(actions, str):
                yml_data['actions'] = [f'{actions}']
            else:
                yml_data['actions'] = ['']  # Empty single-quoted string if no actions

            # Write updated YAML content back to file
            with open(yml_file_path, 'w') as file:
                yaml.dump(yml_data, file, default_flow_style=False)

            print(f"Successfully updated {yml_file_path} with new actions.")
        except Exception as e:
            print(f"Error updating YAML file: {str(e)}")


    def generate_policy_with_updatedyml(self,the_file):
        with open(the_file, 'r') as f:
            cfg = yaml.safe_load(f)
        policy_generated = write_policy_with_template(cfg)
        return policy_generated

    def extract_topic_inresource(self, resources):
        fifth_comma_parts = []
        for item in resources:
            if item == "*":
                fifth_comma_parts.append(item)
                continue
            if len(item) > 1:
                part = re.split(':', item)
                temp_fifth_comma_parts = part[5]
                fifth_comma_parts.append(temp_fifth_comma_parts)
        return fifth_comma_parts

    def has_wildcard(self, resource):
        return any(char in resource for char in ['*', '#', '+'])

    def compare_policies(self, original_dict, generated_dict):
        unsafe_actions = []
        for action, orig_resources in original_dict.items():
            if action in generated_dict:
                gen_resources = generated_dict[action]
                if any(self.has_wildcard(res) for res in orig_resources) and not any(self.has_wildcard(res) for res in gen_resources):
                    unsafe_actions.append(action)


        return unsafe_actions

    def mix_use_detection(self,policy):
        service_in_the_policy = set()
        actions,_,_ = self.extract(policy)
        unconstrain_action = set()
        for action in actions:
            temp = action.split(':')
            service_in_the_policy.add(temp[0])

        for service in service_in_the_policy:
            unconstrain = get_actions_that_support_wildcard_arns_only(service)
            unconstrain_action.append(unconstrain)


        return unconstrain_action

    def mix_use_detection_new(self,policy):
        # Check if the policy is a string, if so, parse it
        if isinstance(policy, str):
            try:
                policy = json.loads(policy)
            except json.JSONDecodeError:
                raise ValueError("Invalid JSON string provided for policy")

        # Extract all statements from the policy
        statements = policy.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]

        # Check each statement for mixed use
        for statement in statements:
            actions = statement.get('Action', [])
            resources = statement.get('Resource', '*')

            # Convert actions to a set if it's a string (single action)
            if isinstance(actions, str):
                actions = {actions}
            else:
                actions = set(actions)

            # Get unique services from the actions
            services = {action.split(':')[0] for action in actions}

            for service in services:
                service_actions = {action for action in actions if action.startswith(f"{service}:")}
                unconstrained_actions = set(get_actions_that_support_wildcard_arns_only(service))
                all_actions = set(get_actions_for_service(service))
                constrained_actions = all_actions - unconstrained_actions

                has_unconstrained = bool(service_actions.intersection(unconstrained_actions))
                has_constrained = bool(service_actions.intersection(constrained_actions))

                if has_unconstrained and has_constrained:
                    return True  # Mixed use detected in this action block

        return False  # No mixed use detected in any action block

    def use(self, input_policy, yml_file_path='action.yml'):
        # Extract actions, resources, and dictionary from input policy
        actions, resources, action_resource_dict = self.extract(input_policy)

        # Update the YAML file with extracted actions
        self.update_yml_file(yml_file_path, actions)

        # Generate new policy based on updated YAML file
        generated_policy = self.generate_policy_with_updatedyml(yml_file_path)

        # Extract actions, resources, and dictionary from generated policy
        gen_actions, gen_resources, gen_action_resource_dict = self.extract(generated_policy)

        # Compare original and generated policies
        #unsafe_actions = self.compare_policies(action_resource_dict, gen_action_resource_dict)
        for action in actions:
            # print(action_resource_dict[action])
            # print(gen_action_resource_dict[action])

            for resource in action_resource_dict[action]:
                # print(resource)
                temp_parts = resource.split(':')
                # print(temp_parts[-1],"00000000")
                for resource1 in gen_action_resource_dict[action]:
                    temp_parts1 = resource1.split(':')
                    # print(temp_parts1[-1],"1111")

                if "*" in temp_parts[-1] and "*" not in temp_parts1[-1]:
                    print(f'{resource},from action {action} ,this resource is not safe')
                    continue

                slash_temp_parts = temp_parts[-1].split('/')
                slash_temp_parts1 = temp_parts1[-1].split('/')
                # print(slash_temp_parts,slash_temp_parts1,'2222')
                for i, part in enumerate(slash_temp_parts1):
                    if "$" in part:
                        # print(part, "333333")
                        if i < len(slash_temp_parts) and isinstance(slash_temp_parts[i], str):
                            print(f"{resource}   this resource is safe")
                        else:
                            print(f"{resource}   this resource is not safe")


        return {
            'original_actions': actions,
            'original_resources': resources,
            'original_action_resource_dict': action_resource_dict,
            'generated_actions': gen_actions,
            'generated_resources': gen_resources,
            'generated_action_resource_dict': gen_action_resource_dict,
            'generated_policy': generated_policy
        }



#test
if __name__ == "__main__":
    extractor = extract_and_output_by_yml()

    results = extractor.use(policy)

    a = extractor.mix_use_detection_new(policy)

    print(a)
    # print("Original Actions:", json.dumps(results['original_actions'],indent=2))
    # print("Generated Actions:", json.dumps(results['generated_actions'],indent=2))
    # print("Original Resources:", json.dumps(results['original_resources'],indent=2))
    # print("Generated Resources:", json.dumps(results['generated_resources'],indent=2))
    # print("Generated Policy:", json.dumps(results['generated_policy'],indent=2))
    # print("unsafe actions:", json.dumps(results['unsafe_actions'],indent=2))
