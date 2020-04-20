import unittest
import json
from policy_sentry.writing.policy_document import PolicyDocument, StatementDetails
from policy_sentry.writing.sid_group_2 import SidGroup2


class PolicyDocumentTestCase(unittest.TestCase):
    def test_policy_document_revised(self):
        # Empty Policy document
        policy_document = PolicyDocument()
        # print(policy_document.json)
        # print(policy_document.all_allowed_actions)
        # print(policy_document.allows_privilege_escalation)
        # print(policy_document.allows_data_leak_actions)
        # print(policy_document.permissions_management_without_constraints)
        # print(policy_document.write_actions_without_constraints)
        # print(policy_document.tagging_actions_without_constraints)
        # print(policy_document.allows_specific_actions_without_constraints(["s3:GetObject"]))

        statement_to_add = {
            "Effect": "Allow",
            "Sid": "Yolo",
            "Resource": "*",
            "Action": "ecr:*"
        }
        policy_document.add_statements(statement_to_add)
        print(json.dumps(policy_document.json, indent=4))

    def test_sid_group_2(self):
        sid_group2 = SidGroup2()
        statement_to_add = {
            "Effect": "Allow",
            "Sid": "Yolo",
            "Resource": "*",
            "Action": "ecr:*"
        }
        sid_group2.add_statements(statement_to_add)
        # print(json.dumps(sid_group2.json, indent=4))
        self.assertTrue(sid_group2.is_valid_sid("Yolo"))

        sid_group2.add_action_without_resource_constraint("s3:GetObject")
        # print(json.dumps(sid_group2.json, indent=4))
        result = sid_group2.json
        expected_result = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Yolo",
                    "Effect": "Allow",
                    "Action": [
                        "ecr:*"
                    ],
                    "Resource": [
                        "*"
                    ]
                },
                {
                    "Sid": "MultMultNone",
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject"
                    ],
                    "Resource": [
                        "*"
                    ]
                }
            ]
        }
        self.assertDictEqual(result, expected_result)
        self.assertTrue(sid_group2.allows_specific_actions_without_constraints(["s3:GetObject"]))
        self.assertTrue(sid_group2.allows_data_leak_actions)

    def test_add_by_arn_and_access_level(self):
        sid_group2 = SidGroup2()
        arn_list = [
            "arn:aws:kms:us-east-1:123456789012:key/123456"
        ]
        sid_group2.add_by_arn_and_access_level(arn_list, "Read")
        expected_results = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "KmsReadKey",
                    "Effect": "Allow",
                    "Action": [
                        "kms:DescribeKey",
                        "kms:GetKeyPolicy",
                        "kms:GetKeyRotationStatus",
                        "kms:GetParametersForImport",
                        "kms:GetPublicKey",
                        "kms:ListResourceTags"
                    ],
                    "Resource": [
                        "arn:aws:kms:us-east-1:123456789012:key/123456"
                    ]
                }
            ]
        }
        self.assertDictEqual(sid_group2.json, expected_results)
        # Reset
        sid_group2 = SidGroup2()
        sid_group2.add_overrides("s3:GetObject")
        expected_results = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "SkipResourceConstraints",
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject"
                    ],
                    "Resource": [
                        "*"
                    ]
                }
            ]
        }
        self.assertDictEqual(sid_group2.json, expected_results)


    def test_refactored_crud_policy(self):
        """test_refactored_crud_policy"""
        sid_group = SidGroup2()
        sid_group.add_by_arn_and_access_level(
            ["arn:aws:secretsmanager:us-east-1:123456789012:secret:mysecret"],
            "Read",
        )
        sid_group.add_by_arn_and_access_level(
            ["arn:aws:s3:::example-org-sbx-vmimport/stuff"], "Tagging"
        )
        sid_group.add_by_arn_and_access_level(
            ["arn:aws:secretsmanager:us-east-1:123456789012:secret:mysecret"],
            "Write",
        )
        sid_group.add_by_arn_and_access_level(
            ["arn:aws:secretsmanager:us-east-1:123456789012:secret:anothersecret"],
            "Write",
        )
        sid_group.add_by_arn_and_access_level(
            ["arn:aws:kms:us-east-1:123456789012:key/123456"],
            "Permissions management",
        )
        sid_group.add_by_arn_and_access_level(
            ["arn:aws:ssm:us-east-1:123456789012:parameter/test"], "List"
        )

        output = sid_group.json
        desired_output = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "SecretsmanagerReadSecret",
                    "Effect": "Allow",
                    "Action": [
                        "secretsmanager:DescribeSecret",
                        "secretsmanager:GetResourcePolicy",
                        "secretsmanager:GetSecretValue",
                        "secretsmanager:ListSecretVersionIds",
                    ],
                    "Resource": [
                        "arn:aws:secretsmanager:us-east-1:123456789012:secret:mysecret"
                    ],
                },
                {
                    "Sid": "S3TaggingObject",
                    "Effect": "Allow",
                    "Action": [
                        "s3:DeleteObjectTagging",
                        "s3:DeleteObjectVersionTagging",
                        "s3:PutObjectTagging",
                        "s3:PutObjectVersionTagging",
                        "s3:ReplicateTags",
                    ],
                    "Resource": ["arn:aws:s3:::example-org-sbx-vmimport/stuff"],
                },
                {
                    "Sid": "SecretsmanagerWriteSecret",
                    "Effect": "Allow",
                    "Action": [
                        "secretsmanager:CancelRotateSecret",
                        "secretsmanager:DeleteSecret",
                        "secretsmanager:PutSecretValue",
                        "secretsmanager:RestoreSecret",
                        "secretsmanager:RotateSecret",
                        "secretsmanager:UpdateSecret",
                        "secretsmanager:UpdateSecretVersionStage",
                    ],
                    "Resource": [
                        "arn:aws:secretsmanager:us-east-1:123456789012:secret:mysecret",
                        "arn:aws:secretsmanager:us-east-1:123456789012:secret:anothersecret",
                    ],
                },
                {
                    "Sid": "KmsPermissionsmanagementKey",
                    "Effect": "Allow",
                    "Action": [
                        "kms:CreateGrant",
                        "kms:PutKeyPolicy",
                        "kms:RetireGrant",
                        "kms:RevokeGrant",
                    ],
                    "Resource": ["arn:aws:kms:us-east-1:123456789012:key/123456"],
                },
            ],
        }
        print(json.dumps(output, indent=4))
        self.maxDiff = None
        self.assertEqual(output, desired_output)

    def test_resource_restriction_plus_dependent_action(self):
        """
        test_resource_restriction_plus_dependent_action
        """
        # Given iam:generateorganizationsaccessreport with resource constraint, make sure these are added:
        #  organizations:DescribePolicy,organizations:ListChildren,organizations:ListParents,
        #  organizations:ListPoliciesForTarget,organizations:ListRoots,organizations:ListTargetsForPolicy
        actions_test_data_1 = ["iam:generateorganizationsaccessreport"]
        sid_group = SidGroup2()
        sid_group.add_by_list_of_actions(actions_test_data_1)
        output = sid_group.json
        desired_output = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "organizations:DescribePolicy",
                        "organizations:ListChildren",
                        "organizations:ListParents",
                        "organizations:ListPoliciesForTarget",
                        "organizations:ListRoots",
                        "organizations:ListTargetsForPolicy",
                    ],
                    "Resource": ["*"],
                    "Sid": "MultMultNone",
                },
                {
                    "Sid": "IamReadAccessreport",
                    "Effect": "Allow",
                    "Action": ["iam:GenerateOrganizationsAccessReport"],
                    "Resource": [
                        "arn:${Partition}:iam::${Account}:access-report/${EntityPath}"
                    ],
                },
            ],
        }
        self.maxDiff = None
        # print(json.dumps(output, indent=4))
        self.assertDictEqual(output, desired_output)



    def test_resource_restriction_plus_dependent_action_simple_2(self):
        """
        test_resource_restriction_plus_dependent_action_simple_2
        """
        # Given iam:generateorganizationsaccessreport with resource constraint, make sure these are added:
        #  organizations:DescribePolicy,organizations:ListChildren,organizations:ListParents,
        #  organizations:ListPoliciesForTarget,organizations:ListRoots,organizations:ListTargetsForPolicy

        sid_group = SidGroup2()
        sid_group.add_by_arn_and_access_level(
            ["arn:aws:iam::000000000000:access-report/somepath"], "Read"
        )
        output = sid_group.json
        desired_output = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "MultMultNone",
                    "Effect": "Allow",
                    "Action": [
                        "organizations:DescribePolicy",
                        "organizations:ListChildren",
                        "organizations:ListParents",
                        "organizations:ListPoliciesForTarget",
                        "organizations:ListRoots",
                        "organizations:ListTargetsForPolicy",
                    ],
                    "Resource": ["*"],
                },
                {
                    "Sid": "IamReadAccessreport",
                    "Effect": "Allow",
                    "Action": ["iam:GenerateOrganizationsAccessReport"],
                    "Resource": ["arn:aws:iam::000000000000:access-report/somepath"],
                },
            ],
        }
        print(json.dumps(output, indent=4))
        self.assertDictEqual(output, desired_output)



    def test_add_by_list_of_actions(self):
        actions_test_data_1 = ["kms:CreateCustomKeyStore", "kms:CreateGrant"]
        sid_group = SidGroup2()
        sid_group.add_by_list_of_actions(actions_test_data_1)
        output = sid_group.json
        desired_output = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "KmsPermissionsmanagementKey",
                    "Effect": "Allow",
                    "Action": ["kms:CreateGrant"],
                    "Resource": [
                        "arn:${Partition}:kms:${Region}:${Account}:key/${KeyId}"
                    ],
                },
                {
                    "Sid": "MultMultNone",
                    "Effect": "Allow",
                    "Action": [
                        "cloudhsm:DescribeClusters",
                        "kms:CreateCustomKeyStore",
                    ],
                    "Resource": ["*"],
                },
            ],
        }
        print(json.dumps(output, indent=4))
        self.maxDiff = None
        self.assertDictEqual(output, desired_output)

