import unittest
import json
from policy_sentry.shared.database import connect_db
from policy_sentry.shared.constants import DATABASE_FILE_PATH
from policy_sentry.writing.conditions_sid_group import ConditionSidGroup
from parliament import analyze_policy_string
import os
from policy_sentry.util.file import read_yaml_file

db_session = connect_db(DATABASE_FILE_PATH)


class ConditionsTestCase(unittest.TestCase):
    def test_condition_eval_from_file(self):
        """write-policy with conditions mode."""
        policy_file_path = os.path.abspath(
                    os.path.join(
                        os.path.dirname(__file__), os.path.pardir + "/" + os.path.pardir + "/examples/yml/conditions.yml",
                    )
                )
        cfg = read_yaml_file(policy_file_path)
        print(json.dumps(cfg, indent=4))
        expected_cfg = {
            'mode': 'conditions',
            'read': [
                'arn:aws:ssm:us-east-1:123456789012:parameter/test'
            ],
            'lazy-conditions': [
                {
                    'condition_key_string': 'ssm:SyncType',
                    'condition_type_string': 'StringLike',
                    'condition_value': 'SyncToDestination'
                }
            ]
        }
        # This doesn't tell us much on purpose, just that the file has not changed
        self.assertDictEqual(expected_cfg, cfg)
        conditions_sid_group = ConditionSidGroup()
        minimize = None
        policy = conditions_sid_group.process_template(db_session, cfg, minimize)
        print(json.dumps(policy, indent=4))
        expected_policy_from_file = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "SsmReadMultSsmsynctypeStringlikeSynctodestination",
                    "Effect": "Allow",
                    "Action": [
                        "ssm:GetParameter",
                        "ssm:GetParameterHistory",
                        "ssm:GetParameters",
                        "ssm:GetParametersByPath",
                        "ssm:ListTagsForResource"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "StringLike": {
                            "ssm:SyncType": "SyncToDestination"
                        }
                    }
                }
            ]
        }
        # This shows us that when we update the yml file template, it will update the rest of it.
        self.assertDictEqual(expected_policy_from_file, policy)

    def test_condition_sid_group(self):
        """writing.conditions_sid_group.ConditionSidGroup"""
        condition_sid_group = ConditionSidGroup()
        arn_list = [
            "arn:${Partition}:ssm:${Region}:${Account}:resource-data-sync/*"
        ]
        access_level = "Write"
        # conditions_block = {"StringLike": {"ssm:SyncType": "SyncToDestination"}}
        # conditions_block = {"StringLike": {"ssm:SyncType": "SyncFromSource"}}
        # conditions_block = {
        #     "condition_key_string": "ssm:SyncType",
        #     "condition_type_string": "StringLike",
        #     "condition_value": "SyncFromSource"
        # }

        conditions_block = [{
            "condition_key_string": "ssm:SyncType",
            "condition_type_string": "StringLike",
            "condition_value": "SyncFromSource"
        }]
        condition_sid_group.add_by_condition_map_and_access_level(db_session, arn_list, access_level, conditions_block)
        # result will be ['ssm:CreateResourceDataSync', 'ssm:DeleteResourceDataSync', 'ssm:UpdateResourceDataSync']
        # print(conditions)
        # print()
        result = condition_sid_group.get_condition_sid_group()
        print(json.dumps(result, indent=4))
        expected_result = {
            "SsmWriteMultSsmsynctypeStringlikeSyncfromsource": {
                "arn": [
                    "arn:${Partition}:ssm:${Region}:${Account}:resource-data-sync/*"
                ],
                "service": "ssm",
                "access_level": "Write",
                "arn_format": "*",
                "actions": [
                    "ssm:CreateResourceDataSync",
                    "ssm:DeleteResourceDataSync",
                    "ssm:UpdateResourceDataSync"
                ],
                "conditions": {
                    "StringLike": {
                        "ssm:SyncType": "SyncFromSource"
                    }
                }
            }
        }
        self.maxDiff = None
        self.assertDictEqual(expected_result, result)

        policy = condition_sid_group.get_rendered_policy(db_session)
        print(json.dumps(policy, indent=4))
        expected_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "SsmWriteMultSsmsynctypeStringlikeSyncfromsource",
                    "Effect": "Allow",
                    "Action": [
                        "ssm:CreateResourceDataSync",
                        "ssm:DeleteResourceDataSync",
                        "ssm:UpdateResourceDataSync"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "StringLike": {
                            "ssm:SyncType": "SyncFromSource"
                        }
                    }
                }
            ]
        }
        self.assertDictEqual(policy, expected_policy)

        policy_string = json.dumps(policy)
        analyzed_policy = analyze_policy_string(policy_string)
        for f in analyzed_policy.findings:
            print(f)
