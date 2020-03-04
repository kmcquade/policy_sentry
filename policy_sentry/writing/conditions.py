# pylint: disable=unused-import,wrong-import-order,missing-module-docstring,no-value-for-parameter,reimported,no-else-raise,missing-function-docstring,logging-format-interpolation,undefined-loop-variable,unused-import,wrong-import-order,unused-argument
import logging
from policy_sentry.shared.database import connect_db
from policy_sentry.querying.conditions import get_condition_key_details, get_condition_keys_for_service, get_condition_value_type
from policy_sentry.querying.actions import get_actions_matching_condition_crud_and_arn, \
    get_actions_matching_condition_key
from policy_sentry.analysis.analyze import determine_actions_to_expand
from policy_sentry.querying.conditions import get_condition_keys_for_service, get_condition_keys_for_service_as_map
from parliament.statement import GLOBAL_CONDITION_KEYS, OPERATORS, get_global_key_type, \
    is_value_in_correct_format_for_type, translate_documentation_types, is_condition_key_match, get_privilege_info
from parliament.misc import make_list
logger = logging.getLogger(__name__)


def validate_condition_map(operator, condition_block, expanded_actions):
    """
    operator is something like "StringLike"
    condition_block is something like {"s3:prefix":["home/${aws:username}/*"]}
    """

    operator_type_requirement = is_valid_operator(operator)

    if operator_type_requirement == "Bool":
        is_mismatched_type_set_to_null(operator, condition_block)

    for key in condition_block:
        check_bad_pattern_for_mfa(operator, key, condition_block)
        # The key here from the example is "s3:prefix"
        condition_type = get_global_key_type(key)
        if condition_type:
            # TODO: Add the service-specific mismatched type check
            check_mismatched_global_condition_type(key, condition_block, operator_type_requirement, operator)
        else:
            # See if this is a service specific key
            # TODO: Add the service-specific mismatched type check

            # TODO: Just see if it's a legit action I guess
            check_mismatched_global_condition_type(key, condition_block, operator_type_requirement, operator)
    # If we've gotten this far, it should be valid - otherwise it would have raised an exception.
    return True


def validate_condition_map_item(db_session, condition_key_string, condition_type_string, condition_value):
    """
    Validate a single item under a condition map. There can be one or more of these per condition map (the block that looks like "Condition" : { <condition_map> })
    :param db_session: SQLAlchemy database session object
    :param condition_key_string: Identifies the condition key whose value will be tested to determine whether the condition is met. AWS defines a set of condition keys that are available in all AWS services, including aws:principaltype, aws:SecureTransport, and aws:userid.
    :param condition_type_string: Identifies the type of condition being tested, such as StringEquals, StringLike, NumericLessThan, DateGreaterThanEquals, Bool, BinaryEquals, IpAddress, ArnEquals, etc.
    :param condition_value: The actual value supplied for the condition - like true, AES256, etc.
    :return:
    """
    is_valid_operator(condition_type_string)
    condition_value_type = get_condition_value_type(db_session, condition_key_string)
    if condition_value_type == "Bool":
        condition_value = condition_value.lower()
    if not is_value_in_correct_format_for_type(condition_value_type, [condition_value]):
        raise Exception(f"Mismatched type: {condition_key_string} requires a value of type {condition_value_type} "
                        f"but {condition_type_string} was supplied.")
    # If we've made it this far, then it hasn't thrown an exception and is probably legit.
    return True


def is_valid_operator(operator):
    """
    :param operator: "StringLike
    :return:
    """
    operator_type_requirement = None
    for documented_operator in OPERATORS:
        op = documented_operator.lower()
        if operator.lower() in [
            op,
            op + "ifexists",
            "forallvalues:" + op,
            "foranyvalue:" + op,
            "forallvalues:" + op + "ifexists",
            "foranyvalue:" + op + "ifexists",
        ]:
            operator_type_requirement = OPERATORS[documented_operator]
            break
    if operator_type_requirement is None:
        # return False
        raise Exception(f"UNKNOWN OPERATOR: The condition operator {operator} is not valid.")
    else:
        return operator_type_requirement


def is_mismatched_type_set_to_null(operator, condition_block):
    value = "{}".format(list(condition_block.values())[0]).lower()
    if value not in ("true", "false"):
        raise Exception(f"MISMATCHED_TYPE_OPERATION_TO_NULL: The operator {operator} is set to None")


def check_bad_pattern_for_mfa(operator, key, condition_block):
    if operator.lower() == "bool":
        if key.lower() == "aws:MultiFactorAuthPresent".lower() and "false" in make_list(
            condition_block[key]
        ):
            raise Exception(
                f'The condition {"Bool": {"aws:MultiFactorAuthPresent":"false"}} is bad because aws:MultiFactorAuthPresent may not exist so it does not enforce MFA. You likely want to use a Deny with BoolIfExists.')
            # self.add_finding( "BAD_PATTERN_FOR_MFA", detail='The condition {"Bool": {
            # "aws:MultiFactorAuthPresent":"false"}} is bad because aws:MultiFactorAuthPresent may not exist so it
            # does not enforce MFA. You likely want to use a Deny with BoolIfExists.', location={"location":
            # condition_block}, )
    elif operator.lower() == "null":
        if key.lower == "aws:MultiFactorAuthPresent".lower() and "false" in make_list(
            condition_block[key]
        ):
            raise Exception(
                f'BAD_PATTERN_FOR_MFA: The condition {"Null": {"aws:MultiFactorAuthPresent":"false"}} is bad because aws:MultiFactorAuthPresent it does not enforce MFA, and only checks if the value exists. You likely want to use an Allow with {"Bool": {"aws:MultiFactorAuthPresent":"true"}}.')
            # self.add_finding( "BAD_PATTERN_FOR_MFA", detail='The condition {"Null": {
            # "aws:MultiFactorAuthPresent":"false"}} is bad because aws:MultiFactorAuthPresent it does not enforce
            # MFA, and only checks if the value exists. You likely want to use an Allow with {"Bool": {
            # "aws:MultiFactorAuthPresent":"true"}}.', location={"location": condition_block}, )


def check_mismatched_service_condition_type(key, condition_block, operator_type_requirement, operator, expanded_actions):
    """
    Breaking out the second part of check_mismatched_type

    :param key:
    :param condition_block:
    :param operator_type_requirement:
    :param operator:
    :param expanded_actions:
    :return:
    """

    # See if this is a service specific key
    for action in expanded_actions:
        service_prefix, action_name = action.split(":")
        privilege_info = get_privilege_info(
            service_prefix, action_name
        )

        # Ensure the condition_key exists
        match = None
        for resource_type in privilege_info["resource_types"]:
            for condition_key in resource_type["condition_keys"]:
                if is_condition_key_match(condition_key, key):
                    match = condition_key

        if match is None:
            logger.debug("UNKNOWN_CONDITION_FOR_ACTION: Unknown condition {} for action {}:{}".format(
                    key, service_prefix, action_name
                ))
            continue

        condition_type = None
        for condition in privilege_info["service_conditions"]:
            if condition["condition"] == match:
                condition_type = condition["type"]

        if condition_type is None:
            raise Exception(
                "Action condition not found in service definition for {}".format(
                    condition
                )
            )

    if not is_value_in_correct_format_for_type(
        condition_type, make_list(condition_block[key])
    ):
        raise Exception("MISMATCHED_TYPE: Type mismatch: {} requires a value of type {} but given {}".format(
            key, condition_type, condition_block[key]
        ))
    if condition_type is not None:
        # if operator_type_requirement.lower() == 'string' and condition_type.lower() = 'arn':
        #     # Ignore these.
        #     pass
        if operator_type_requirement != translate_documentation_types(
            condition_type
        ):
            raise Exception("MISMATCHED_TYPE: Type mismatch: {} requires a value of type {} but given {}".format(
                operator,
                operator_type_requirement,
                translate_documentation_types(condition_type),
            ))


def check_mismatched_global_condition_type(key, condition_block, operator_type_requirement, operator, expanded_actions):
    # The key here from the example is "s3:prefix"
    condition_type = get_global_key_type(key)
    if condition_type:
        # This is a global key, like aws:CurrentTime
        # Check if the values match the type (ex. must all be Date values)
        if not is_value_in_correct_format_for_type(
            condition_type, make_list(condition_block[key])
        ):
            raise Exception("MISMATCHED_TYPE: Type mismatch: {} requires a value of type {} but given {}".format(
                key, condition_type, condition_block[key]
            ))
            # self.add_finding(
            #     "MISMATCHED_TYPE",
            #     detail="Type mismatch: {} requires a value of type {} but given {}".format(
            #         key, condition_type, condition_block[key]
            #     ),
            #     location={"location": condition_block},
            # )
    else:
        check_mismatched_service_condition_type(key, condition_block, operator_type_requirement, operator, expanded_actions)


def check_unknown_condition_for_action(privilege_info, action_struct, key):
    # Ensure the condition_key exists
    match = None
    for resource_type in privilege_info["resource_types"]:
        for condition_key in resource_type["condition_keys"]:
            if is_condition_key_match(condition_key, key):
                match = condition_key

    if match is None:
        raise Exception("UNKNOWN_CONDITION_FOR_ACTION: Unknown condition {} for action {}:{}".format(
            key, action_struct["service"], action_struct["action"]
        ))
    return match


def check_action_condition_not_found(privilege_info, match):
    condition_type = None

    for condition in privilege_info["service_conditions"]:
        if condition["condition"] == match:
            condition_type = condition["type"]

    if condition_type is None:
        raise Exception(
            "Action condition not found in service definition for {}".format(condition)
        )
