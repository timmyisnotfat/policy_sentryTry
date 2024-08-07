from policy_sentry.shared.iam_data import get_service_prefix_data
import json

if __name__ == '__main__':
    resultS3 = get_service_prefix_data("iot")
    print(json.dumps(resultS3, indent=4))
