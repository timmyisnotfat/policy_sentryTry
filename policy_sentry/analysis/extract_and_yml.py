import json
import yaml

policy = '''
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "ssm:GetParameter",
            "Resource": [
                "arn:aws:ssm:eu-west-1:435775406265:parameter/lambda/vsure/login",
                "arn:aws:ssm:eu-west-1:435775406265:parameter/lambda/vsure/password"
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

        if isinstance(policy, str):
            try:
                policy = json.loads(policy)
            except json.JSONDecodeError:
                print("Error: Invalid JSON string")
                return

        if isinstance(policy, dict):
            statements = policy.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]

            for statement in statements:
                if statement.get('Effect') == 'Allow':
                    actions = statement.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    the_actions.extend(actions)

                    resources = statement.get('Resource', [])
                    if isinstance(resources, str):
                        resources = [resources]
                    the_resources.extend(resources)

        # print("Actions:", the_actions)
        # print("Resources:", the_resources)
        return the_actions,the_resources

    def update_yml_file(self, yml_file_path, actions):
        try:
            # Read existing YAML content
            with open(yml_file_path, 'r') as file:
                yml_data = yaml.safe_load(file)

            # Update the actions in the YAML data
            yml_data['actions'] = actions

            # Write updated YAML content back to file
            with open(yml_file_path, 'w') as file:
                yaml.dump(yml_data, file, default_flow_style=False)

            print(f"Successfully updated {yml_file_path} with new actions.")
        except Exception as e:
            print(f"Error updating YAML file: {str(e)}")


# Test the class
extractor = extract_and_output_by_yml()
a, b = extractor.extract(policy)
yml_file_path = 'action.yml'
extractor.update_yml_file(yml_file_path, a)



# print(policy)
