"""
Just a common storage space for storing some constants.
"""
from pathlib import Path
import os

# General Folders
HOME = str(Path.home())
CONFIG_DIRECTORY = os.path.join(HOME, ".policy_sentry")

# HTML Docs
BUNDLED_HTML_DIRECTORY_PATH = os.path.join(
    str(Path(os.path.dirname(__file__))), "data", "docs"
)
BUNDLED_DATA_DIRECTORY = os.path.join(str(Path(os.path.dirname(__file__))), "data")

LOCAL_HTML_DIRECTORY_PATH = os.path.join(CONFIG_DIRECTORY, "data", "docs")

BASE_DOCUMENTATION_URL = "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_actions-resources-contextkeys.partial.html"

# Data json file
BUNDLED_DATASTORE_FILE_PATH = os.path.join(
    str(Path(os.path.dirname(__file__))), "data", "iam-definition.json"
)
LOCAL_DATASTORE_FILE_PATH = os.path.join(CONFIG_DIRECTORY, "iam-definition.json")
if os.path.exists(LOCAL_DATASTORE_FILE_PATH):
    DATASTORE_FILE_PATH = LOCAL_DATASTORE_FILE_PATH
else:
    DATASTORE_FILE_PATH = BUNDLED_DATASTORE_FILE_PATH

# Overrides
BUNDLED_ACCESS_OVERRIDES_FILE = os.path.join(
    os.path.abspath(os.path.dirname(__file__)), "data", "access-level-overrides.yml"
)

LOCAL_ACCESS_OVERRIDES_FILE = os.path.join(
    CONFIG_DIRECTORY, "access-level-overrides.yml"
)

# Policy constants
# https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_version.html
POLICY_LANGUAGE_VERSION = "2012-10-17"


READ_ONLY_DATA_LEAK_ACTIONS = [
    "s3:GetObject",
    "ssm:GetParameter",
    "ssm:GetParameters",
    "ssm:GetParametersByPath",
    "secretsmanager:GetSecretValue"
]

PRIVILEGE_ESCALATION_METHODS = {
    # 1. IAM Permissions on Other Users
    "CreateAccessKey": ["iam:createaccesskey"],
    "CreateLoginProfile": ["iam:createloginprofile"],
    "UpdateLoginProfile": ["iam:updateloginprofile"],
    # 2. Permissions on Policies
    "CreateNewPolicyVersion": ["iam:createpolicyversion"],
    "SetExistingDefaultPolicyVersion": ["iam:setdefaultpolicyversion"],
    "AttachUserPolicy": ["iam:attachuserpolicy"],
    "AttachGroupPolicy": ["iam:attachgrouppolicy"],
    "AttachRolePolicy": ["iam:attachrolepolicy", "sts:assumerole"],
    "PutUserPolicy": ["iam:putuserpolicy"],
    "PutGroupPolicy": ["iam:putgrouppolicy"],
    "PutRolePolicy": ["iam:putrolepolicy", "sts:assumerole"],
    "AddUserToGroup": ["iam:addusertogroup"],
    # 3. Updating an AssumeRolePolicy
    "UpdateRolePolicyToAssumeIt": ["iam:updateassumerolepolicy", "sts:assumerole"],
    # 4. iam:PassRole:*
    "CreateEC2WithExistingIP": ["iam:passrole", "ec2:runinstances"],
    "PassExistingRoleToNewLambdaThenInvoke": [
        "iam:passrole",
        "lambda:createfunction",
        "lambda:invokefunction",
    ],
    "PassExistingRoleToNewLambdaThenTriggerWithNewDynamo": [
        "iam:passrole",
        "lambda:createfunction",
        "lambda:createeventsourcemapping",
        "dynamodb:createtable",
        "dynamodb:putitem",
    ],
    "PassExistingRoleToNewLambdaThenTriggerWithExistingDynamo": [
        "iam:passrole",
        "lambda:createfunction",
        "lambda:createeventsourcemapping",
    ],
    "PassExistingRoleToNewGlueDevEndpoint": [
        "iam:passrole",
        "glue:createdevendpoint",
    ],
    "PassExistingRoleToCloudFormation": [
        "iam:passrole",
        "cloudformation:createstack",
    ],
    "PassExistingRoleToNewDataPipeline": [
        "iam:passrole",
        "datapipeline:createpipeline",
    ],
    # 5. Privilege Escalation Using AWS Services
    "UpdateExistingGlueDevEndpoint": ["glue:updatedevendpoint"],
    "EditExistingLambdaFunctionWithRole": ["lambda:updatefunctioncode"],
}
