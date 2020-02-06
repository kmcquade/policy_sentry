import unittest
from policy_sentry.command.write_policy import print_policy
from policy_sentry.shared.constants import DATABASE_FILE_PATH
from policy_sentry.shared.database import connect_db
from policy_sentry.writing.conditions import check_condition
from policy_sentry.writing.validate import check_crud_schema
from policy_sentry.writing.policy import ArnActionGroup
from policy_sentry.util.file import read_yaml_file
from os.path import dirname, abspath, join, pardir
from pathlib import Path
db_session = connect_db(DATABASE_FILE_PATH)

class ConditionsTestCase(unittest.TestCase):
    def test_conditions_file(self):
        policy_file_path = abspath(join(dirname(__file__), pardir + '/examples/yml/crud-with-conditions.yml'))
        cfg = read_yaml_file(policy_file_path)
        check_crud_schema(cfg)
        arn_action_group = ArnActionGroup()
        arn_dict = arn_action_group.process_resource_specific_acls(cfg, db_session)
        print(arn_dict)
        policy = print_policy(arn_dict, db_session)
        print(policy)

        # policy = print_policy(arn_dict, db_session)
#     def test_check_condition(self):
#         # operator = "StringLike"
#         # condition_block = {"s3:prefix": ["home/${aws:username}/*"]}
#         # expanded_actions = ["s3:*"]
#         # result = check_condition(operator, condition_block, expanded_actions)
#         # print(result)
#         print()
#         arn_action_group = ArnActionGroup()
#         arn_list_from_user = ["arn:aws:s3:::example-org-s3-access-logs"]
#         lazy_condition_block = {
#
#         }
#         access_level = "Write"
#         arn_action_group.add(db_session, arn_list_from_user, access_level)
#         arn_action_group.update_actions_for_raw_arn_format(db_session)
#         arn_action_group.add_universal_conditions()


    # def test_check_bad_pattern_for_mfa(self):
    #     print()
    #     # Fail case
    #     # Pass case
    #
    # def test_mismatched_type(self):
    #     print()
    #     # Fail case
    #     # Pass case
    #
    # def test_check_unknown_action_for_condition(self):
    #     print()
    #     # Fail case
    #     # Pass case
    #
    # def check_action_condition_not_found(self):
    #     print()
