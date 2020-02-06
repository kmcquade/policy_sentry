from policy_sentry.shared.database import connect_db
from policy_sentry.querying.conditions import get_condition_key_details, get_condition_keys_for_service
from policy_sentry.querying.actions import get_actions_matching_condition_crud_and_arn, \
    get_actions_matching_condition_key
from policy_sentry.analysis.analyze import determine_actions_to_expand
from parliament.statement import GLOBAL_CONDITION_KEYS, OPERATORS, get_global_key_type, \
    is_value_in_correct_format_for_type, translate_documentation_types, is_condition_key_match, get_privilege_info
from parliament.misc import make_list


#
# def is_lazy_condition_format_correct(db_session, action_list, condition_key_string, condition_type_string, condition_value):
#     """
#     Determine if condition key is valid.
#
#     :param db_session: SQL Alchemy database session
#     :param condition_key_string: Like "ec2:ResourceTag/purpose"
#     :param condition_type_string: Like "StringEquals"
#     :param condition_value: Like "test". We have to validate the format here.
#     :return:
#
#     """
#     # Prep it for the Parliament terminology
#     # https://github.com/duo-labs/parliament/blob/01b20a57f66b537189e3e3a86c05db70ca9d59b2/parliament/statement.py#L864
#     condition_block = {condition_type_string: condition_value}
#     condition = condition_key_string
#     expanded_actions = determine_actions_to_expand(db_session, action_list)
#     result = check_condition(condition, condition_block, expanded_actions)


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
    if value != "true" and value != "false":
        raise Exception(f"MISMATCHED_TYPE_OPERATION_TO_NULL: The operator {operator} is set to None")


def check_condition(operator, condition_block, expanded_actions):
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
            check_mismatched_type(key, condition_block, operator_type_requirement, operator)
        else:
            # See if this is a service specific key
            # TODO: Just see if it's a legit action I guess
            check_mismatched_type(key, condition_block, operator_type_requirement, operator)
    # If we've gotten this far, it should be valid - otherwise it would have raised an exception.
    return True


def check_bad_pattern_for_mfa(operator, key, condition_block):
    if operator.lower() == "bool":
        if key.lower() == "aws:MultiFactorAuthPresent".lower() and "false" in make_list(
            condition_block[key]
        ):
            raise Exception(
                f'The condition {"Bool": {"aws:MultiFactorAuthPresent":"false"}} is bad because aws:MultiFactorAuthPresent may not exist so it does not enforce MFA. You likely want to use a Deny with BoolIfExists.')
            # self.add_finding(
            #     "BAD_PATTERN_FOR_MFA",
            #     detail='The condition {"Bool": {"aws:MultiFactorAuthPresent":"false"}} is bad because aws:MultiFactorAuthPresent may not exist so it does not enforce MFA. You likely want to use a Deny with BoolIfExists.',
            #     location={"location": condition_block},
            # )
    elif operator.lower() == "null":
        if key.lower == "aws:MultiFactorAuthPresent".lower() and "false" in make_list(
            condition_block[key]
        ):
            raise Exception(
                f'BAD_PATTERN_FOR_MFA: The condition {"Null": {"aws:MultiFactorAuthPresent":"false"}} is bad because aws:MultiFactorAuthPresent it does not enforce MFA, and only checks if the value exists. You likely want to use an Allow with {"Bool": {"aws:MultiFactorAuthPresent":"true"}}.')
            # self.add_finding(
            #     "BAD_PATTERN_FOR_MFA",
            #     detail='The condition {"Null": {"aws:MultiFactorAuthPresent":"false"}} is bad because aws:MultiFactorAuthPresent it does not enforce MFA, and only checks if the value exists. You likely want to use an Allow with {"Bool": {"aws:MultiFactorAuthPresent":"true"}}.',
            #     location={"location": condition_block},
            # )


def check_mismatched_type(key, condition_block, operator_type_requirement, operator):
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

"""
Scott's privilege_info example:

{
	'access_level': 'Read',
	'description': 'Grants permission to check the availability of multiple image layers in a specified registry and repository',
	'privilege': 'BatchCheckLayerAvailability',
	'resource_types': [
		{
		'condition_keys': [],
		'dependent_actions': [],
		'resource_type': 'repository*'
		}
	],
	'service_resources': [
		{
			'arn': 'arn:${Partition}:ecr:${Region}:${Account}:repository/${RepositoryName}',
			'condition_keys': [
				'aws:ResourceTag/${TagKey}',
				'ecr:ResourceTag/${TagKey}'
			],
			'resource': 'repository'
		}
	],
	'service_conditions': [
		{
			'condition': 'aws:RequestTag/${TagKey}',
			'description': 'Filters create requests based on the allowed set of values for each of the tags.',
			'type': 'String'
		}, {
			'condition': 'aws:ResourceTag/${TagKey}',
			'description': 'Filters actions based on tag-value associated with the resource.',
			'type': 'String'
		}, {
			'condition': 'aws:TagKeys',
			'description': 'Filters create requests based on the presence of mandatory tags in the request.',
			'type': 'String'
		}, {
			'condition': 'ecr:ResourceTag/${TagKey}',
			'description': 'Filters actions based on tag-value associated with the resource.',
			'type': 'String'
		}
	]
}
"""
