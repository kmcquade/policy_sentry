from policy_sentry.writing.policy_document import PolicyDocument
from policy_sentry.writing.sid_group import get_wildcard_only_actions_matching_services_and_access_level
from policy_sentry.util.arns import does_arn_match, get_service_from_arn
from policy_sentry.util.text import capitalize_first_character
from policy_sentry.querying.actions import (
    get_action_data,
    get_actions_with_arn_type_and_access_level,
    get_dependent_actions,
)
from policy_sentry.querying.arns import get_resource_type_name_with_raw_arn
import logging
import re


logger = logging.getLogger(__name__)


class SidGroup2(PolicyDocument):
    def __init__(self, policy=None):
        # PolicyDocument.__init__(self, policy)
        super().__init__(policy)
        self.overrides = []
        self.wildcard_only_single_actions = []
        # When a user requests all wildcard-only actions available under a service at a specific access level
        self.wildcard_only_service_read = []
        self.wildcard_only_service_write = []
        self.wildcard_only_service_list = []
        self.wildcard_only_service_tagging = []
        self.wildcard_only_service_permissions_management = []

    def add_overrides(self, overrides):
        """
        To override resource constraint requirements - i.e., instead of restricting s3:PutObject to a path and
        allowing s3:PutObject to * resources, put s3:GetObject here.
        """
        if isinstance(overrides, list):
            pass
        elif isinstance(overrides, str):
            overrides = [overrides]
        else:
            raise Exception("Please provide 'overrides' as a list of IAM actions.")

        for override_action in overrides:
            if override_action not in self.overrides:
                self.overrides.append(override_action)
            self.add_action_without_resource_constraint(override_action, "SkipResourceConstraints")

    @property
    def overrides_lowercase(self):
        lowercase_overrides = [x.lower() for x in self.overrides]
        return lowercase_overrides

    def add_requested_service_wide(self, service_prefixes, access_level):
        """
        When a user requests all wildcard-only actions available under a service at a specific access level

        :param service_prefixes: A list of service prefixes
        :param access_level: The requested access level
        """
        if access_level == "Read":
            self.wildcard_only_service_read = service_prefixes
        elif access_level == "Write":
            self.wildcard_only_service_write = service_prefixes
        elif access_level == "List":
            self.wildcard_only_service_list = service_prefixes
        elif access_level == "Tagging":
            self.wildcard_only_service_tagging = service_prefixes
        elif access_level == "Permissions management":
            self.wildcard_only_service_permissions_management = service_prefixes

    def add_by_arn_and_access_level(
        self, arn_list, access_level, conditions_block=None
    ):
        """
        This adds the user-supplied ARN(s), service prefixes, access levels, and condition keys (if applicable) given
        by the user. It derives the list of IAM actions based on the user's requested ARNs and access levels.

        :param arn_list: Just a list of resource ARNs.
        :param access_level: "Read", "List", "Tagging", "Write", or "Permissions management"
        :param conditions_block: Optionally, a condition block with one or more conditions
        """
        for arn in arn_list:
            service_prefix = get_service_from_arn(arn)
            service_action_data = get_action_data(service_prefix, "*")
            for service_prefix in service_action_data:
                for row in service_action_data[service_prefix]:
                    if (
                        does_arn_match(arn, row["resource_arn_format"])
                        and row["access_level"] == access_level
                    ):
                        raw_arn_format = row["resource_arn_format"]
                        resource_type_name = get_resource_type_name_with_raw_arn(
                            raw_arn_format
                        )
                        sid_namespace = create_policy_sid_namespace(
                            service_prefix, access_level, resource_type_name
                        )
                        actions = get_actions_with_arn_type_and_access_level(
                            service_prefix, resource_type_name, access_level
                        )
                        # Make supplied actions lowercase
                        # supplied_actions = [x.lower() for x in actions]
                        supplied_actions = actions.copy()
                        dependent_actions = get_dependent_actions(supplied_actions)
                        # List comprehension to get all dependent actions that are not in the supplied actions.
                        dependent_actions = [
                            x for x in dependent_actions if x not in supplied_actions
                        ]
                        if len(dependent_actions) > 0:
                            for dep_action in dependent_actions:
                                self.add_action_without_resource_constraint(dep_action, "MultMultNone")
                        if sid_namespace in self.sids:
                            # If the ARN already exists there, skip it.
                            if arn not in self.get_resources_from_sid(sid_namespace):
                                self.add_resource_by_sid(sid_namespace, arn)
                        # If it did not exist before at all, create it.
                        else:
                            temp_sid_dict = {
                                "Resource": [arn],
                                "Sid": sid_namespace,
                                "Effect": "Allow",
                                "Action": actions,
                            }
                            self.add_statements(temp_sid_dict)

    def add_action_without_resource_constraint(
        self, action, sid_namespace="MultMultNone"
    ):
        """
        This handles the cases where certain actions do not handle resource constraints - either by AWS, or for
        flexibility when adding dependent actions.

        :param action: The single action to add to the SID namespace. For instance, s3:ListAllMyBuckets
        :param sid_namespace: MultMultNone by default. Other valid option is "SkipResourceConstraints"
        """
        if sid_namespace == "SkipResourceConstraints":
            temp_sid_dict = {
                "Resource": ["*"],
                "Sid": "SkipResourceConstraints",
                "Effect": "Allow",
                "Action": [action],
            }
        elif sid_namespace == "MultMultNone":
            temp_sid_dict = {
                "Resource": ["*"],
                "Sid": "MultMultNone",
                "Effect": "Allow",
                "Action": [action],
            }
        else:
            raise Exception(
                "Please specify the sid_namespace as either 'SkipResourceConstraints' or "
                "'MultMultNone'."
            )
        if isinstance(action, str):
            if sid_namespace in self.sids:
                if action.lower() not in self.get_lowercase_expanded_actions_from_sid(sid_namespace):
                    print(f"Adding action {action} to sid_namespace {sid_namespace}")
                    self.add_action_by_sid(sid_namespace, action)
            else:
                print(f"Adding the statement {temp_sid_dict}")
                self.add_statements(temp_sid_dict)
        else:
            raise Exception("Please provide the action as a string, not a list.")
        return self.sids

    def add_by_list_of_actions(self, supplied_actions):
        """
        Takes a list of actions, queries the database for corresponding arns, adds them to the object.

        :param supplied_actions: A list of supplied actions
        """
        dependent_actions = get_dependent_actions(supplied_actions)
        dependent_actions = [x for x in dependent_actions if x not in supplied_actions]
        logger.debug("Adding by list of actions")
        logger.debug(f"Supplied actions: {str(supplied_actions)}")
        logger.debug(f"Dependent actions: {str(dependent_actions)}")
        arns_matching_supplied_actions = []

        for action in supplied_actions:
            service_name, action_name = action.split(":")
            action_data = get_action_data(service_name, action_name)
            for row in action_data[service_name]:
                if row["resource_arn_format"] not in arns_matching_supplied_actions:
                    arns_matching_supplied_actions.append(
                        {
                            "resource_arn_format": row["resource_arn_format"],
                            "access_level": row["access_level"],
                            "action": row["action"],
                        }
                    )

        # Identify the actions that do not support resource constraints
        # If that's the case, add it to the wildcard namespace. Otherwise, don't add it.
        actions_without_resource_constraints = []
        for item in arns_matching_supplied_actions:
            if item["resource_arn_format"] != "*":
                self.add_by_arn_and_access_level(
                    [item["resource_arn_format"]], item["access_level"]
                )
            else:
                actions_without_resource_constraints.append(item["action"])

        # If there are any dependent actions, we need to add them without resource constraints.
        # Otherwise, we get into issues where the amount of extra SIDs will balloon.
        # Also, the user has no way of knowing what those dependent actions are beforehand.
        if len(dependent_actions) > 0:
            for dep_action in dependent_actions:
                self.add_action_without_resource_constraint(dep_action)
        # Now, because add_by_arn_and_access_level() adds all actions under an access level, we have to
        # remove all actions that do not match the supplied_actions. This is done in-place.
        logger.debug(
            "Purging actions that do not match the requested actions and dependent actions"
        )
        logger.debug(f"Supplied actions: {str(supplied_actions)}")
        logger.debug(f"Dependent actions: {str(dependent_actions)}")
        self.remove_actions_not_matching_these(supplied_actions + dependent_actions)
        for action in actions_without_resource_constraints:
            logger.debug(
                f"Deliberately adding the action {action} without resource constraints"
            )
            self.add_action_without_resource_constraint(action)
        logger.debug(
            "Removing actions that are in the wildcard arn (Resources = '*') as well as other statements that have "
            "resource constraints "
        )
        self.remove_actions_duplicated_in_wildcard_arn()
        logger.debug("Getting the rendered policy")
        return self.json

    def remove_actions_duplicated_in_wildcard_arn(self):
        """
        Removes actions from the object that are in a resource-specific ARN, as well as the `*` resource.
        For example, if ssm:GetParameter is restricted to a specific parameter path, as well as `*`, then we want to
        remove the `*` option to force least privilege.
        """
        actions_under_wildcard_resources = []
        actions_under_wildcard_resources_to_nuke = []

        # Build a temporary list. Contains actions in MultMultNone SID (where resources = "*")
        for sid in self.sids:
            if sid == "MultMultNone" or sid == "SkipResourceConstraints":
                actions_under_wildcard_resources.extend(self.get_expanded_actions_from_sid(sid))

        # If the actions under the MultMultNone SID exist under other SIDs
        if len(actions_under_wildcard_resources) > 0:
            for sid in self.sids:
                if "*" not in self.get_resources_from_sid(sid):
                    for action in actions_under_wildcard_resources:
                        if action.lower() in self.get_lowercase_expanded_actions_from_sid(sid):
                            if action not in self.overrides_lowercase:
                                # add it to a list of actions to nuke when they are under other SIDs
                                actions_under_wildcard_resources_to_nuke.append(action)

        # If there are actions that we need to remove from SIDs outside of MultMultNone SID
        if len(actions_under_wildcard_resources_to_nuke) > 0:
            for sid in self.sids:
                if "*" in self.get_resources_from_sid(sid):
                    for action in actions_under_wildcard_resources_to_nuke:
                        try:
                            self.remove_action_from_sid(sid, action)
                        except BaseException:  # pylint: disable=broad-except
                            logger.debug("Removal not successful")


def create_policy_sid_namespace(
    service, access_level, resource_type_name, condition_block=None
):
    """
    Simply generates the SID name. The SID groups ARN types that share an access level.

    For example, S3 objects vs. SSM Parameter have different ARN types - as do S3 objects vs S3 buckets. That's how we
    choose to group them.

    :param service: "ssm"
    :param access_level: "Read"
    :param resource_type_name: "parameter"
    :param condition_block: {"condition_key_string": "ec2:ResourceTag/purpose", "condition_type_string":
    "StringEquals", "condition_value": "test"}
    :return: SsmReadParameter
    :rtype: str
    """
    # Sanitize the resource_type_name; otherwise we hit some list conversion
    # errors
    resource_type_name = re.sub("[^A-Za-z0-9]+", "", resource_type_name)
    # Also remove the space from the Access level, if applicable. This only
    # applies for "Permissions management"
    access_level = re.sub("[^A-Za-z0-9]+", "", access_level)
    sid_namespace_prefix = (
        capitalize_first_character(service)
        + capitalize_first_character(access_level)
        + capitalize_first_character(resource_type_name)
    )

    if condition_block:
        condition_key_namespace = re.sub(
            "[^A-Za-z0-9]+", "", condition_block["condition_key_string"]
        )
        condition_type_namespace = condition_block["condition_type_string"]
        condition_value_namespace = re.sub(
            "[^A-Za-z0-9]+", "", condition_block["condition_value"]
        )
        sid_namespace_condition_suffix = (
            f"{capitalize_first_character(condition_key_namespace)}"
            f"{capitalize_first_character(condition_type_namespace)}"
            f"{capitalize_first_character(condition_value_namespace)}"
        )
        sid_namespace = sid_namespace_prefix + sid_namespace_condition_suffix
    else:
        sid_namespace = sid_namespace_prefix
    return sid_namespace

#
# def process_sid_group_2_template(template):
#
