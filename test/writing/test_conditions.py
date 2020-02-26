import unittest
import json
from policy_sentry.shared.database import connect_db
from policy_sentry.shared.constants import DATABASE_FILE_PATH
from policy_sentry.writing.conditions import is_valid_operator, check_mismatched_global_condition_type, \
    is_mismatched_type_set_to_null, check_bad_pattern_for_mfa
from parliament.misc import make_list

db_session = connect_db(DATABASE_FILE_PATH)

expanded_s3_actions = [
    "s3:AbortMultipartUpload",
    "s3:BypassGovernanceRetention",
    "s3:CreateAccessPoint",
    "s3:CreateBucket",
    "s3:CreateJob",
    "s3:DeleteAccessPoint",
    "s3:DeleteAccessPointPolicy",
    "s3:DeleteBucket",
    "s3:DeleteBucketPolicy",
    "s3:DeleteBucketWebsite",
    "s3:DeleteObject",
    "s3:DeleteObjectTagging",
    "s3:DeleteObjectVersion",
    "s3:DeleteObjectVersionTagging",
    "s3:DescribeJob",
    "s3:GetAccelerateConfiguration",
    "s3:GetAccessPoint",
    "s3:GetAccessPointPolicy",
    "s3:GetAccessPointPolicyStatus",
    "s3:GetAccountPublicAccessBlock",
    "s3:GetAnalyticsConfiguration",
    "s3:GetBucketAcl",
    "s3:GetBucketCORS",
    "s3:GetBucketLocation",
    "s3:GetBucketLogging",
    "s3:GetBucketNotification",
    "s3:GetBucketObjectLockConfiguration",
    "s3:GetBucketPolicy",
    "s3:GetBucketPolicyStatus",
    "s3:GetBucketPublicAccessBlock",
    "s3:GetBucketRequestPayment",
    "s3:GetBucketTagging",
    "s3:GetBucketVersioning",
    "s3:GetBucketWebsite",
    "s3:GetEncryptionConfiguration",
    "s3:GetInventoryConfiguration",
    "s3:GetLifecycleConfiguration",
    "s3:GetMetricsConfiguration",
    "s3:GetObject",
    "s3:GetObjectAcl",
    "s3:GetObjectLegalHold",
    "s3:GetObjectRetention",
    "s3:GetObjectTagging",
    "s3:GetObjectTorrent",
    "s3:GetObjectVersion",
    "s3:GetObjectVersionAcl",
    "s3:GetObjectVersionForReplication",
    "s3:GetObjectVersionTagging",
    "s3:GetObjectVersionTorrent",
    "s3:GetReplicationConfiguration",
    "s3:ListAccessPoints",
    "s3:ListAllMyBuckets",
    "s3:ListBucket",
    "s3:ListBucketMultipartUploads",
    "s3:ListBucketVersions",
    "s3:ListJobs",
    "s3:ListMultipartUploadParts",
    "s3:ObjectOwnerOverrideToBucketOwner",
    "s3:PutAccelerateConfiguration",
    "s3:PutAccessPointPolicy",
    "s3:PutAccountPublicAccessBlock",
    "s3:PutAnalyticsConfiguration",
    "s3:PutBucketAcl",
    "s3:PutBucketCORS",
    "s3:PutBucketLogging",
    "s3:PutBucketNotification",
    "s3:PutBucketObjectLockConfiguration",
    "s3:PutBucketPolicy",
    "s3:PutBucketPublicAccessBlock",
    "s3:PutBucketRequestPayment",
    "s3:PutBucketTagging",
    "s3:PutBucketVersioning",
    "s3:PutBucketWebsite",
    "s3:PutEncryptionConfiguration",
    "s3:PutInventoryConfiguration",
    "s3:PutLifecycleConfiguration",
    "s3:PutMetricsConfiguration",
    "s3:PutObject",
    "s3:PutObjectAcl",
    "s3:PutObjectLegalHold",
    "s3:PutObjectRetention",
    "s3:PutObjectTagging",
    "s3:PutObjectVersionAcl",
    "s3:PutObjectVersionTagging",
    "s3:PutReplicationConfiguration",
    "s3:ReplicateDelete",
    "s3:ReplicateObject",
    "s3:ReplicateTags",
    "s3:RestoreObject",
    "s3:UpdateJobPriority",
    "s3:UpdateJobStatus"
]

class ConditionsTestCase(unittest.TestCase):
    def test_make_list(self):
        """parliament.misc.make_list"""
        example = {"s3:prefix": ["home/${aws:username}/*"]}
        result = make_list(example)
        desired_result = [{'s3:prefix': ['home/${aws:username}/*']}]
        self.assertEqual(desired_result, result)
        print(result)

    def test_is_valid_operator(self):
        """
        writing.conditions.is_valid_operator
        """
        self.assertTrue(is_valid_operator("StringLike"))
        self.assertTrue(is_valid_operator("StringNotEquals"))
        self.assertTrue(is_valid_operator("NumericEquals"))
        self.assertTrue(is_valid_operator("NumericNotEquals"))
        self.assertTrue(is_valid_operator("DateEquals"))
        self.assertTrue(is_valid_operator("DateNotEquals"))
        self.assertTrue(is_valid_operator("StringLike"))
        self.assertTrue(is_valid_operator("Bool"))
        self.assertTrue(is_valid_operator("Null"))
        self.assertTrue(is_valid_operator("BinaryEquals"))
        self.assertTrue(is_valid_operator("IpAddress"))
        self.assertTrue(is_valid_operator("ArnEquals"))

        # Weird cases
        self.assertTrue(is_valid_operator("IPADDRESS"))
        self.assertTrue(is_valid_operator("STRINGLIKE"))
        self.assertTrue(is_valid_operator("StRiNgLiKe"))

        with self.assertRaises(Exception):
            is_valid_operator("Kinnaird")

    def test_is_mismatched_type_set_to_null(self):
        """writing.conditions.is_mismatched_type_set_to_null"""
        with self.assertRaises(Exception):
            first_case = is_mismatched_type_set_to_null("bool", {"Null": {"aws:MultiFactorAuthPresent": "false"}})
            print(first_case)

    def test_check_bad_pattern_for_mfa(self):
        """writing.conditions.check_bad_pattern_for_mfa"""
        with self.assertRaises(Exception):
            first_case = is_mismatched_type_set_to_null("bool", {"Bool": {"aws:MultiFactorAuthPresent": "false"}})
            print(first_case)
        with self.assertRaises(Exception):
            second_case = is_mismatched_type_set_to_null("null", {"Null": {"aws:MultiFactorAuthPresent": "false"}})
            print(second_case)

    def test_check_unknown_condition_for_action(self):
        """writing.conditions.check_unknown_condition_for_action"""

    def test_check_mismatched_global_condition_type(self):
        """writing.conditions.check_mismatched_global_condition_type"""
        # CASE 1: Global type
        key = "aws:CurrentTime"
        condition_block = {"aws:CurrentTime": "2019-07-16T12:00:00Z"}
        operator_type_requirement = "Date"
        operator = "DateGreaterThan"
        result = check_mismatched_global_condition_type(key, condition_block, operator_type_requirement, operator, expanded_s3_actions)
        self.assertIsNone(result)

    def test_check_mismatched_service_condition_type(self):
        """writing.conditions.check_mismatched_service_condition_type"""
        # CASE 2: service-specific
        key = "s3:prefix"
        condition_block = {"s3:prefix": ["home/${aws:username}/*"]}
        operator_type_requirement = "String"
        operator = "StringLike"
        result = check_mismatched_global_condition_type(key, condition_block, operator_type_requirement, operator, expanded_s3_actions)
        self.assertIsNone(result)

        # # CASE 3: FAILING CASE
        key = "s3:prefix"
        condition_block = {"s3:prefix": ["home/${aws:username}/*"]}
        operator_type_requirement = "Date"  # This will cause it to fail
        operator = "StringLike"
        with self.assertRaises(Exception):
            result = check_mismatched_global_condition_type(key, condition_block, operator_type_requirement, operator, expanded_s3_actions)

