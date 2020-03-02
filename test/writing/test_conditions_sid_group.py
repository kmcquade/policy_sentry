import unittest
import json
from policy_sentry.shared.database import connect_db
from policy_sentry.shared.constants import DATABASE_FILE_PATH
from policy_sentry.writing.conditions_sid_group import ConditionSidGroup
db_session = connect_db(DATABASE_FILE_PATH)


class ConditionsTestCase(unittest.TestCase):
    def test_condition_sid_group(self):
        """writing.conditions_sid_group.ConditionSidGroup"""
        condition_sid_group = ConditionSidGroup()
        arn_list = [
            "arn:${Partition}:ssm:${Region}:${Account}:resource-data-sync/${SyncName}"
        ]
        access_level = "Write"
        # conditions_block = {"StringLike": {"ssm:SyncType": "SyncToDestination"}}
        # conditions_block = {"StringLike": {"ssm:SyncType": "SyncFromSource"}}
        conditions_block = {
            "condition_key_string": "ssm:SyncType",
            "condition_type_string": "StringLike",
            "condition_value": "SyncFromSource"
        }
        condition_sid_group.add_by_condition_map_and_access_level(db_session, arn_list, access_level, conditions_block)
        # result will be ['ssm:CreateResourceDataSync', 'ssm:DeleteResourceDataSync', 'ssm:UpdateResourceDataSync']
        # print(conditions)
        # print()
        result = condition_sid_group.get_condition_sid_group()
        print(json.dumps(result, indent=4))
        expected_result = {
            "SsmWriteMultSsmsynctypeStringlikeSyncfromsource": {
                "arn": [
                    "arn:${Partition}:ssm:${Region}:${Account}:resource-data-sync/${SyncName}"
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
                    "SsmsynctypeStringlikeSyncfromsource": {
                        "StringLike": {
                            "ssm:SyncType": "SyncFromSource"
                        }
                    }
                }
            }
        }

        self.assertDictEqual(expected_result, result)
