# pylint: disable=unused-import,wrong-import-order,missing-module-docstring,no-value-for-parameter,reimported,no-else-raise,missing-function-docstring,logging-format-interpolation,undefined-loop-variable,unused-import,wrong-import-order,unused-argument,unused-variable
from policy_sentry.querying.all import get_all_actions
from policy_sentry.writing.minimize import minimize_statement_actions
from policy_sentry.shared.constants import POLICY_LANGUAGE_VERSION
from policy_sentry.util.arns import get_service_from_arn, does_arn_match, get_resource_from_arn
from policy_sentry.util.actions import get_full_action_name
from policy_sentry.querying.actions import get_action_data
from policy_sentry.querying.conditions import get_conditions_for_action_and_raw_arn
from policy_sentry.writing.sid_group import create_policy_sid_namespace
from policy_sentry.util.text import capitalize_first_character
import re
from policy_sentry.writing.validate import check_conditions_schema, validate_condition_block
import logging
logger = logging.getLogger(__name__)


class ConditionSidGroup:
    """
    Trying out a different strategy for Condition keys.

    Let's try doing condition keys without Resource block constraints.
    """
    def __init__(self):
        self.sids = {}
        self.universal_conditions = {}

    def get_condition_sid_group(self):
        """
        Get the whole SID group as JSON
        """
        return self.sids

    def get_sid(self, sid):
        """Get a single group by the SID identifier"""
        if self.sids[sid]:
            return self.sids[sid]
        else:
            raise Exception(f"No SID with the value of {sid}")

    def list_condition_sids(self):
        """
        Get a list of all of them by their identifiers

        :rtype: list
        """
        return self.sids.keys()

    def get_universal_conditions(self):
        """
        Get the universal conditions maps back as a dict

        :rtype: dict
        """
        return self.universal_conditions

    def process_template(self, db_session, cfg, minimize=None):
        """

        :param db_session:
        :param cfg:
        :param minimize:
        :return:
        """
        if "mode" in cfg.keys():
            if cfg["mode"] == "conditions":
                check_conditions_schema(cfg)
                # TODO: Figure out how to handle the wildcard-only stuff here.

                # TODO: Figure out how to handle the condition block in the template.

                # TODO: Validate the universal conditions blocks
                # TODO: Pass them in as a list to all of these below.
                # Then have the backend logic apply it wherever possible.
                if "lazy-conditions" not in cfg.keys():
                    raise Exception("You must include the lazy-conditions block in the template! Try again.")
                for condition_block in cfg["lazy-conditions"]:
                    validate_condition_block(cfg["lazy-conditions"])
                if "read" in cfg.keys():
                    if cfg["read"] is not None and cfg["read"][0] != "":
                        self.add_by_condition_map_and_access_level(
                            db_session, cfg["read"], "Read", cfg["lazy-conditions"]
                        )
                if "write" in cfg.keys():
                    if cfg["write"] is not None and cfg["write"][0] != "":
                        self.add_by_condition_map_and_access_level(
                            db_session, cfg["write"], "Write", cfg["lazy-conditions"]
                        )
                if "list" in cfg.keys():
                    if cfg["list"] is not None and cfg["list"][0] != "":
                        self.add_by_condition_map_and_access_level(
                            db_session, cfg["list"], "List", cfg["lazy-conditions"]
                        )
                if "permissions-management" in cfg.keys():
                    if (
                        cfg["permissions-management"] is not None
                        and cfg["permissions-management"][0] != ""
                    ):
                        self.add_by_condition_map_and_access_level(
                            db_session,
                            cfg["permissions-management"],
                            "Permissions management",
                            cfg["lazy-conditions"]
                        )
                if "tagging" in cfg.keys():
                    if cfg["tagging"] is not None and cfg["tagging"][0] != "":
                        self.add_by_condition_map_and_access_level(
                            db_session, cfg["tagging"], "Tagging", cfg["lazy-conditions"]
                        )
        rendered_policy = self.get_rendered_policy(db_session, minimize)
        return rendered_policy

    def get_rendered_policy(self, db_session, minimize=None):
        """
        Get the JSON rendered policy

        :param db_session: SQLAlchemy database session
        :param minimize: Reduce the character count of policies without creating overlap with other action names
        :rtype: dict
        """
        statements = []
        # Only set the actions to lowercase if minimize is provided
        all_actions = get_all_actions(db_session, lowercase=True)

        # render the policy
        for sid in self.sids:
            actions = self.sids[sid]["actions"]
            conditions_block = self.sids[sid]["conditions"]
            if len(actions) == 0:
                continue
            if minimize is not None and isinstance(minimize, int):
                actions = minimize_statement_actions(
                    actions, all_actions, minchars=minimize
                )
            statements.append(
                {
                    "Sid": sid,
                    "Effect": "Allow",
                    "Action": actions,
                    "Resource": "*",
                    "Condition": conditions_block,
                }
            )
        policy = {"Version": POLICY_LANGUAGE_VERSION, "Statement": statements}
        return policy

    def add_by_condition_map_and_access_level(self, db_session, arn_list, access_level, conditions_block):
        """

        :param db_session: SQLAlchemy database session
        :param access_level: "Read", "List", "Tagging", "Write", or "Permissions management"
        :param conditions_block: a condition block with one or more conditions
        :return:
        """

        '''
        Process for determining valid conditions
        * Is the operator legit in general?
        * Is it a legit AWS Condition in general?
        * Is it a legit service specific condition in general?
        * Is the value type legit?

        * Correct matches:
            * Is the value in the correct format? (Date should equal date)
            * Does the operator type match the condition type requirements?
            * Does the
        Get a list of actions that correspond to the condition
        Add it to the actions that we will support
        '''
        # condition_block:
        # {
        # "condition_key_string": "ec2:ResourceTag/purpose",
        # "condition_operator": "StringEquals",
        # "condition_value": "test"
        # }
        # You have to provide a valid ARN - and it will grab all actions that would usually apply to that ARN, but then just give it to you based on conditions.

        # arn_list = [
        #     "arn:${Partition}:ssm:${Region}:${Account}:resource-data-sync/${SyncName}"
        # ]
        # access_level = "Write"
        # conditions_block = {"StringLike": {"ssm:SyncType": "SyncToDestination"}}

        actions_corresponding_to_condition = []
        stuff = {}
        for condition_block in conditions_block:
            for arn in arn_list:

                service_prefix = get_service_from_arn(arn)
                service_action_data = get_action_data(db_session, service_prefix, "*")
                for service_prefix in service_action_data:
                    for row in service_action_data[service_prefix]:
                        if (
                            does_arn_match(arn, row["resource_arn_format"])
                            and row["access_level"] == access_level
                        ):
                            actions_corresponding_to_condition.append(row["action"])

                sid_namespace = create_policy_sid_namespace(
                    service_prefix,
                    access_level,
                    "Mult",  # TODO: Figure out if I need to restrict it more? Resource_type_name maybe?
                    condition_block
                )
                condition_dict = {
                    condition_block["condition_type_string"]: {condition_block["condition_key_string"]: condition_block["condition_value"]}
                }
                print(sid_namespace)
                temp_sid_dict = {
                    "arn": [arn],
                    "service": service_prefix,
                    "access_level": access_level,
                    "arn_format": "*",
                    "actions": actions_corresponding_to_condition,
                    "conditions": condition_dict,
                }
                # TODO: In the rendered policy, you should account for instances where StringLike might be used twice or something.
                if sid_namespace in self.sids:
                    logger.debug(f"sid_namespace {sid_namespace} is in self.sids")
                    # If StringLike is already in there, see if ssm:SyncType is under StringLike
                    if condition_block["condition_type_string"] in self.sids[sid_namespace]["conditions"]:
                        # If ["StringLike"]["ssm:SyncType"] exists, then see if "SyncFromSource" is a value under that
                        if condition_block["condition_key_string"] in self.sids[sid_namespace]["conditions"][condition_block["condition_type_string"]]:
                            if condition_block["condition_value"] not in self.sids[sid_namespace]["conditions"][condition_block["condition_type_string"]][condition_block["condition_key_string"]]:
                                # TODO: Let's not deal with lists for now
                                if isinstance(self.sids[sid_namespace]["conditions"][condition_block["condition_type_string"]][condition_block["condition_key_string"]], str):
                                    self.sids[sid_namespace]["conditions"][condition_block["condition_type_string"]][
                                        condition_block["condition_key_string"]] = condition_block["condition_value"]
                        else:
                            self.sids[sid_namespace]["conditions"][condition_block["condition_type_string"]] = {condition_block["condition_key_string"]: condition_block["condition_value"]}
                    elif condition_block["condition_type_string"] not in self.sids[sid_namespace]["conditions"]:
                        self.sids[sid_namespace]["conditions"][condition_block["condition_type_string"]] = {condition_block["condition_key_string"]: condition_block["condition_value"]}
                    # if condition_namespace not in self.sids[sid_namespace]["conditions"]:
                    #     logger.debug(f"sid_namespace {sid_namespace} is in self.sids")
                    #     self.sids[sid_namespace]["conditions"][condition_namespace] = condition_dict
                if sid_namespace not in self.sids:
                    self.sids[sid_namespace] = temp_sid_dict

            # # print(actions_corresponding_to_condition)
            # # ['ssm:CreateResourceDataSync', 'ssm:DeleteResourceDataSync', 'ssm:UpdateResourceDataSync']
            # some_conditions = []
            # for action in actions_corresponding_to_condition:
            #     conditions = get_conditions_for_action_and_raw_arn(db_session, action.lower(), "*")
            #     some_conditions.extend(conditions)
            #     # if not conditions:



                #     print(conditions)
            # return some_conditions
            # Add all actions_corresponding_to_condition, but with the condition block specified
                # for condition_map in conditions_block:
                #     # TODO: Validate stuff. For dev, let's assume they are all legit values
                #     is_valid_operator(condition_map["condition_operator"])
                #     is_valid_condition_key(condition_map["condition_key_string"])


#
# def is_valid_operator(condition_operator):
#     print()
#
#
# def is_valid_condition_key(condition_key_string):
#     is_global = is_global_condition(condition_key_string)
#     is_service = is_service_condition(condition_key_string)
#
#
# def is_global_condition(condition_key_string):
#     print()
#     return
#
#
# def is_service_condition(condition_key_string):
#     print()
#
#
# def is_valid_value_type(condition_key_type):
#     print()
