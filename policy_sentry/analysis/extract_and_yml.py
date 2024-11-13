import json
import yaml
from policy_sentry.command.write_policy import write_policy_with_template
from policy_sentry.querying.actions import get_actions_that_support_wildcard_arns_only
from policy_sentry.querying.actions import get_actions_for_service
from policy_sentry.analysis.expand import expand
from pathlib import Path
import re


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

                    for action in actions:
                        if ':*' in action:
                            extended_actions = expand(action)
                            the_actions.extend(extended_actions)
                            # Associate all expanded actions with the original resources
                            for expanded_action in extended_actions:
                                if expanded_action not in ac_re_dict:
                                    ac_re_dict[expanded_action] = set(resources)
                                else:
                                    ac_re_dict[expanded_action].update(resources)
                        else:
                            the_actions.append(action)
                            if action not in ac_re_dict:
                                ac_re_dict[action] = set(resources)
                            else:
                                ac_re_dict[action].update(resources)

                    # Extend the resources list
                    the_resources.extend(resources)

        # Remove duplicates from lists
        the_actions = list(dict.fromkeys(the_actions))
        the_resources = list(dict.fromkeys(the_resources))

        # Convert sets to lists in the dictionary
        for action in ac_re_dict:
            ac_re_dict[action] = list(ac_re_dict[action])

        # print(f'The actions: {the_actions}')
        # print(f'Action-Resource Dictionary: {json.dumps(ac_re_dict, indent=2)}')

        return the_actions, the_resources, ac_re_dict

    def extract_denied(self,policy):
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
                # Changed from 'Allow' to 'Deny' to extract denied actions
                if statement.get('Effect') == 'Deny':
                    actions = statement.get('Action', [])
                    resources = statement.get('Resource', [])

                    # Ensure actions and resources are lists
                    if isinstance(actions, str):
                        actions = [actions]
                    if isinstance(resources, str):
                        resources = [resources]

                    for action in actions:
                        if ':*' in action:
                            extended_actions = expand(action)
                            the_actions.extend(extended_actions)
                            # Associate all expanded actions with the original resources
                            for expanded_action in extended_actions:
                                if expanded_action not in ac_re_dict:
                                    ac_re_dict[expanded_action] = set(resources)
                                else:
                                    ac_re_dict[expanded_action].update(resources)
                        else:
                            the_actions.append(action)
                            if action not in ac_re_dict:
                                ac_re_dict[action] = set(resources)
                            else:
                                ac_re_dict[action].update(resources)

                    # Extend the resources list
                    the_resources.extend(resources)

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

        if isinstance(policy, str):
            try:
                policy = json.loads(policy)
            except json.JSONDecodeError:
                raise ValueError("Invalid JSON string provided for policy")


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

    def split_the_resource(self,resource):
        comma_part = resource.split(':')
        slash_part = comma_part[-1].split('/')
        just_slash_part = resource.split('/')
        return comma_part,slash_part,just_slash_part

    def if_deny_check(self, policy):
        deny_actions = []
        deny_resources = []
        deny_dict = {}
        if_flaw = True

        allow_actions, allow_resources, allow_dict = self.extract(policy)

        if isinstance(policy, str):
            try:
                policy = json.loads(policy)
            except json.JSONDecodeError:
                print("Error: Invalid JSON string")
                return if_flaw

        if isinstance(policy, dict):
            statements = policy.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]

            for statement in statements:
                if statement.get('Effect') == 'Deny':
                    actions = statement.get('Action', [])
                    resources = statement.get('Resource', [])

                    # Ensure actions and resources are lists
                    if isinstance(actions, str):
                        actions = [actions]
                    if isinstance(resources, str):
                        resources = [resources]

                    deny_actions.extend(actions)
                    deny_resources.extend(resources)

                    for action in actions:
                        if action not in deny_dict:
                            deny_dict[action] = set(resources)
                        else:
                            deny_dict[action].update(resources)

        # Remove duplicates
        deny_actions = list(dict.fromkeys(deny_actions))
        deny_resources = list(dict.fromkeys(deny_resources))

        # Convert sets to lists in deny_dict
        for action in deny_dict:
            deny_dict[action] = list(deny_dict[action])

        # print(f"Deny actions: {deny_actions}")
        # print(f"Deny resources: {deny_resources}")
        # print(f"Deny action-resource dictionary: {json.dumps(deny_dict, indent=2)}")

        # print(allow_dict['iot:Subscribe'])
        # print(deny_dict['iot:Subscribe'])

        if 'iot:Subscribe' not in deny_actions:
            # return True, deny_actions, deny_resources, deny_dict
            return True
        else:
            for denied_resource in deny_dict.get('iot:Subscribe', []):
                for allowed_resource in allow_dict.get('iot:Subscribe', []):
                    _, _, slash_denied = self.split_the_resource(denied_resource)
                    # print(f'just_denied: {slash_denied}')
                    _, _, slash_allowed = self.split_the_resource(allowed_resource)
                    # print(f'just_allowed: {slash_allowed}')
                    if slash_denied[0] == slash_allowed[0] and slash_denied[1] == slash_allowed[1]:
                        if slash_denied[-1] == '*' or '#' or '+':
                            if_flaw = False
                        if slash_denied[-2] == '*' or '#' or '+':
                            if_flaw = False
        #return if_flaw, deny_actions, deny_resources, deny_dict

        return if_flaw

    def publish_check(self,policy):
        if_flaw = False
        allow_actions, allow_resources, allow_dict = self.extract(policy)
        denied_actions, denied_resources, denied_dict = self.extract_denied(policy)
        print(allow_dict['iot:Publish'])
        if 'iot:Publish' in allow_actions:
            for resource in allow_dict['iot:Publish']:
                if '*' in resource:
                    if_flaw = True

        return if_flaw

    def if_onlyiotcore_action(self,policy):
        if_iot = True
        iot_action = [
            'iot:Subscribe',
            'iot:Connect',
            'iot:DeleteThingShadow',
            'iotjobsdata:DescribeJobExecution',
            'iotjobsdata:GetPendingJobExecutions',
            'iot:GetRetainedMessage',
            'iot:GetThingShadow',
            'iot:ListNamedShadowsForThing',
            'iot:ListRetainedMessages',
            'iot:Publish',
            'iot:Receive',
            'iot:RetainPublish',
            'iotjobsdata:StartNextPendingJobExecution',
            'iotjobsdata:UpdateJobExecution',
            'iot:UpdateThingShadow',
            'iot:AssumeRoleWithCertificate'
        ]

        actions, _,_ = self.extract(policy)
        for action in actions:
            if action not in iot_action:
                if_iot = False
                return if_iot
        return if_iot

    def generate_iotpolicywithvariable(self,policy,yml_file_path='geniot_action.yml'):
        # NEED to implement a function that check if there is a file named "geniot_action.yml" in this directory
        if self.if_onlyiotcore_action(policy):
            actions,_,_ = self.extract(policy)
            self.update_yml_file('geniot_action.yml',actions)
            generate_policy = self.generate_policy_with_updatedyml(yml_file_path)
            gen_ac, gen_poli, acpoli_dic = self.extract(generate_policy)
            print(acpoli_dic)
            for action in gen_ac:
                resources = acpoli_dic[action]
                if isinstance(resources, list):
                    # Join the list elements with '/' if it's a list of path components
                    resource_str = '/'.join(str(r) for r in resources)
                else:
                    resource_str = str(resources)
                slash_parts = resource_str.split('/')
                # print(slash_parts)
                if slash_parts[-1] == '${ThingName}':
                    variable_part = '${iot:Connection.Thing.ThingName}'
                elif slash_parts[-1] == '${ClientId}':
                    variable_part = '${iot:ClientId}'
                elif slash_parts[-1] == '${TopicFilter}':
                    variable_part = '${iot:ClientId}'
                elif slash_parts[-1] == '${TopicName}':
                    variable_part = '${iot:ClientId}'

                if '*' not in slash_parts:
                    updated_resource = slash_parts[0] + '/' + variable_part
                    acpoli_dic[action] = updated_resource
                else:
                    updated_resource = '*'
                    acpoli_dic[action] = updated_resource
            for action in gen_ac:
                print(f'{action}:{acpoli_dic[action]}')

                # Generate the final policy document with separate statements
                policy_document = {
                    "Version": "2012-10-17",
                    "Statement": []
                }

                # Create individual statements for each action-resource pair
                for action in gen_ac:
                    statement = {
                        "Effect": "Allow",
                        "Action": action,
                        "Resource": acpoli_dic[action]
                    }
                    policy_document["Statement"].append(statement)



        return policy_document

    def use(self, input_policy, yml_file_path='action.yml'):
        # Extract actions, resources, and dictionary from input policy
        actions, resources, action_resource_dict = self.extract(input_policy)
        a_flaw_policy = False

        if self.if_deny_check(input_policy) == True:

            # Update the YAML file with extracted actions
            self.update_yml_file(yml_file_path, actions)

            # Generate new policy based on updated YAML file
            generated_policy = self.generate_policy_with_updatedyml(yml_file_path)
            print(f'the generated policy: \n{json.dumps(generated_policy,indent=2)}')
            # Extract actions, resources, and dictionary from generated policy
            gen_actions, gen_resources, gen_action_resource_dict = self.extract(generated_policy)

            # Compare original and generated policies
            #unsafe_actions = self.compare_policies(action_resource_dict, gen_action_resource_dict)
            for action in actions:
                # print(action_resource_dict[action])
                # print(gen_action_resource_dict[action])
                '''shall be modify!!!!!!!!!!!!''''''shall be modify!!!!!!!!!!!!''''''shall be modify!!!!!!!!!!!!'''
                if action not in gen_action_resource_dict:
                    print(f"Warning: Action {action} not found in generated policy. Assuming it requires '*' resource.")
                    gen_action_resource_dict[action] = ['*']
                    '''shall be modify!!!!!!!!!!!!''''''shall be modify!!!!!!!!!!!!''''''shall be modify!!!!!!!!!!!!''''''shall be modify!!!!!!!!!!!!'''

                for resource in action_resource_dict[action]:
                    # print(resource)
                    temp_parts = resource.split(':')
                    # print(temp_parts[-1],"00000000")
                    for resource1 in gen_action_resource_dict[action]:
                        temp_parts1 = resource1.split(':')
                        # print(temp_parts1[-1],"1111")

                    if "*" in temp_parts[-1] and "*" not in temp_parts1[-1]:
                        print(f'{resource},from action {action} ,this resource is not safe')
                        a_flaw_policy = True
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
                                a_flaw_policy = True

        else:
            return False


        # return {
        #     'original_actions': actions,
        #     'original_resources': resources,
        #     'original_action_resource_dict': action_resource_dict,
        #     'generated_actions': gen_actions,
        #     'generated_resources': gen_resources,
        #     'generated_action_resource_dict': gen_action_resource_dict,
        #     'generated_policy': generated_policy,
        #     'if_flaw': a_flaw_policy
        # }
        return a_flaw_policy

    def analyze_policies(self):
        all_files = list(Path('F:/pHDfiles/forY/IoTscript/policy_files_new').rglob('*.json'))
        results = []
        output_dir = Path('F:/pHDfiles/forY/IoTscript/mix_used_json')
        output_dir.mkdir(exist_ok=True)
        mixed_use_count = 0

        for file_path in all_files:
            try:
                with open(file_path, 'r') as f:
                    policy = json.load(f)

                detection_result = self.mix_use_detection_new(policy)
                results.append({
                    'file': str(file_path),
                    'result': detection_result
                })
                print(f"Analyzed: {file_path}")

                if detection_result:
                    mixed_use_count += 1
                    new_file_name = file_path.name
                    target_path = output_dir / new_file_name

                    # Only check for duplicates if we found mixed use
                    if target_path.exists():
                        print(f"Skipping {new_file_name} - already exists in mix_used_json")
                        continue

                    # Copy file if it's a new mixed-use case
                    with open(file_path, 'r') as source, open(target_path, 'w') as target:
                        target.write(source.read())
                    print(f"Copied mixed-use policy to: {target_path}")

            except Exception as e:
                print(f"Error analyzing {file_path}: {str(e)}")

        print(f"\nTotal files with mixed use detected: {mixed_use_count}")
        return results


#test
if __name__ == "__main__":

    policy = '''
    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iot:Connect",
                "iot:DeleteThingShadow",
                "iot:GetRetainedMessage",
                "iot:GetThingShadow",
                "iot:ListNamedShadowsForThing",
                "iot:ListRetainedMessages",
                "iot:RetainPublish",
                "iotjobsdata:StartNextPendingJobExecution",
                "iotjobsdata:UpdateJobExecution",
                "iot:UpdateThingShadow",
                "iotjobsdata:GetPendingJobExecutions",
                "iotjobsdata:DescribeJobExecution"
            ],
            "Resource": [
                "arn:aws:iot:us-east-1:123456789012:client/${iot:Connection.Thing.ThingName}"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "iot:Publish"
            ],
            "Resource": [
                "arn:aws:iot:us-east-1:123456789012:topic/${iot:Certificate.Subject.CommonName}"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "iot:Subscribe"
            ],
            "Resource": [
                "arn:aws:iot:us-east-1:123456789012:topicfilter/devices/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "iot:Receive"
            ],
            "Resource": [
                "arn:aws:iot:us-east-1:123456789012:topic/*"
            ]
        }
    ],
    "Expected": {
        "NotReceive": "${iot:Certificate.Subject.CommonName}/any-device"
    }
}
    '''

    extractor = extract_and_output_by_yml()
    #
    results = extractor.generate_iotpolicywithvariable(policy)
    print(json.dumps(results, indent=2))


    # a = extractor.generate_policy_with_updatedyml('action.yml')
    # print(results)
    # print(results)
    #
    # a = extractor.mix_use_detection_new(policy)
    #
    # print(results['if_flaw'])



    # print("Original Actions:", json.dumps(results['original_actions'],indent=2))
    # print("Generated Actions:", json.dumps(results['generated_actions'],indent=2))
    # print("Original Resources:", json.dumps(results['original_resources'],indent=2))
    # print("Generated Resources:", json.dumps(results['generated_resources'],indent=2))
    # print("Generated Policy:", json.dumps(results['generated_policy'],indent=2))
    # print("unsafe actions:", json.dumps(results['unsafe_actions'],indent=2))
