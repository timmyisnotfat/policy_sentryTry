from policy_sentry.analysis.analyze import analyze_by_access_level
from policy_sentry.analysis.expand import expand
from policy_sentry.analysis.expand import expand, determine_actions_to_expand ,get_expanded_policy
import json

if __name__ == '__main__':
    permissions_management_policy = {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloud9:*",
        "s3:Get*"
      ],
      "Resource": "*"
    }
  ]
}
    permissions_management_actions = expand("*")
    print(json.dumps(permissions_management_actions, indent=4))

    # permissions_management_actions = get_expanded_policy(permissions_management_policy)
    # print(json.dumps(permissions_management_actions, indent=4))

