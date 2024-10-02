import json
import yaml
from policy_sentry.command.write_policy import write_policy_with_template
import re

policy = '''
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "iot:Subscribe",
            "Resource": [
                "arn:aws:iot:eu-west-1:435775406265:topicfilter/lambda/vsure/login",
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
                "iot:Connect",
                "iot:Publish"
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


# Test the class
extractor = extract_and_output_by_yml()
a, b, c = extractor.extract(policy)
yml_file_path = 'action.yml'
# print(a)
extractor.update_yml_file(yml_file_path, a)
results = extractor.generate_policy_with_updatedyml(yml_file_path)
actions, resources,diction = extractor.extract(results)
# print(f'the resources:{resources}')
print(json.dumps(c,indent=2))
# print(json.dumps(results,indent=2))
print(json.dumps(diction,indent=2))

for action in actions:
    if "*" in c[action]:
        print('an unsafe Original Policy')

    print(c[action])
    print(diction[action],'\n')

# print(json.dumps(resources,indent=2))
# print(json.dumps(b,indent=2))


# print(policy)
