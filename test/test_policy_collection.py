import unittest
from policy_sentry.shared.policy_collection import PolicyCollection, process_actions_cfg
from policy_sentry.shared.constants import DATABASE_FILE_PATH
from policy_sentry.shared.database import connect_db
from policy_sentry.shared.actions import get_dependent_actions
from policy_sentry.command.write_policy import print_policy

db_session = connect_db(DATABASE_FILE_PATH)


class PolicyCollectionTestCase(unittest.TestCase):
    def test_add_s3_permissions_management_arn_policy_collection(self):
        """policy_group_add_s3_permissions_management_arn: Testing ArnActionGroup, but with PolicyGroup instead"""
        policy_collection = PolicyCollection()
        arn_list_from_user = ["arn:aws:s3:::example-org-s3-access-logs"]
        access_level = "Permissions management"
        desired_output = [
            {
                'arn': 'arn:aws:s3:::example-org-s3-access-logs',
                'service': 's3',
                'access_level': 'Permissions management',
                'arn_format': 'arn:${Partition}:s3:::${BucketName}',
                'actions': [
                    's3:deletebucketpolicy',
                    's3:putbucketacl',
                    's3:putbucketpolicy',
                    's3:putbucketpublicaccessblock'
                ]
            }
        ]
        policy_collection.add_crud_entry(db_session, arn_list_from_user, access_level)
        print(policy_collection.get_arns())
        self.maxDiff = None
        self.assertEqual(policy_collection.get_arns(), desired_output)

    def test_get_policy_elements_policy_collection(self):
        policy_collection = PolicyCollection()
        arn_list_from_user = ["arn:aws:s3:::example-org-s3-access-logs"]
        access_level = "Permissions management"
        desired_output = {
            'S3PermissionsmanagementBucket':
                {
                    'name': 'S3PermissionsmanagementBucket',
                    'actions': [
                        's3:deletebucketpolicy',
                        's3:putbucketacl',
                        's3:putbucketpolicy',
                        's3:putbucketpublicaccessblock'
                    ],
                    'arns': [
                        'arn:aws:s3:::example-org-s3-access-logs'
                    ]
                }
        }
        policy_collection.add_crud_entry(db_session, arn_list_from_user, access_level)
        arn_dict = policy_collection.get_policy_elements(db_session)
        print(arn_dict)
        self.assertEqual(arn_dict, desired_output)

    def test_print_policy_with_actions_having_dependencies_policy_collection(self):
        desired_output = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "KmsPermissionsmanagementKmskey",
                        "Effect": "Allow",
                        "Action": [
                            "kms:creategrant"
                        ],
                        "Resource": [
                            "arn:${Partition}:kms:${Region}:${Account}:key/${KeyId}"
                        ]
                    },
                    {
                        "Sid": "MultMultNone",
                        "Effect": "Allow",
                        "Action": [
                            "kms:createcustomkeystore",
                            "cloudhsm:describeclusters"
                        ],
                        "Resource": [
                            "*"
                        ]
                    }
                ]
            }
        supplied_actions = ['kms:CreateCustomKeyStore', 'kms:CreateGrant']
        supplied_actions = get_dependent_actions(db_session, supplied_actions)
        arn_dict = process_actions_cfg(supplied_actions, db_session)
        self.maxDiff = None
        policy = print_policy(arn_dict, db_session)
        self.assertDictEqual(policy, desired_output)
