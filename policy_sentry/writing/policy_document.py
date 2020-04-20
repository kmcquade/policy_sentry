import logging
from policy_sentry.analysis.analyze import determine_actions_to_expand
from policy_sentry.querying.actions import remove_actions_not_matching_access_level
from policy_sentry.writing.utils import (
    remove_read_level_actions,
    remove_wildcard_only_actions,
    remove_actions_not_matching_access_level
)
from policy_sentry.querying.all import get_all_actions

from policy_sentry.querying.actions import get_camelcase_action
from policy_sentry.querying.arns import get_resource_type_name_with_raw_arn
from policy_sentry.shared.constants import READ_ONLY_DATA_LEAK_ACTIONS, PRIVILEGE_ESCALATION_METHODS, POLICY_LANGUAGE_VERSION
from policy_sentry.writing.minimize import minimize_statement_actions
logger = logging.getLogger(__name__)

all_actions = get_all_actions(lowercase=True)
BLANK_POLICY = {
    "Version": POLICY_LANGUAGE_VERSION, "Statement": []
}


class PolicyDocument:
    """
    Holds the actual AWS IAM Policy document
    """

    def __init__(self, policy=None):
        if policy is None:
            policy = BLANK_POLICY

        statement_structure = policy.get("Statement", [])
        self.original_policy = policy
        self.policy = policy
        self.statements = []
        if not isinstance(statement_structure, list):
            statement_structure = [statement_structure]

        for statement in statement_structure:
            self.statements.append(StatementDetails(statement))

    def add_statements(self, statements):
        if not isinstance(statements, list):
            statements = [statements]
        for statement in statements:
            self.statements.append(StatementDetails(statement))

    def is_valid_sid(self, sid):
        result = False
        for statement in self.statements:
            if statement.sid == sid:
                result = True
                break
        return result

    def add_action_by_sid(self, sid, action):
        if self.is_valid_sid(sid):
            for statement in self.statements:
                if statement.sid == sid:
                    statement.actions.append(action)
        else:
            raise Exception("The sid %s is not valid" % sid)
        print()

    def add_resource_by_sid(self, sid, resource):
        for statement in self.statements:
            if statement.sid == sid:
                statement.add_resource(resource)

    def get_lowercase_expanded_actions_from_sid(self, sid):
        actions = []
        for statement in self.statements:
            if statement.sid == sid:
                actions.extend(statement.lowercase_expanded_actions)
                break
        return actions

    def get_expanded_actions_from_sid(self, sid):
        actions = []
        for statement in self.statements:
            if statement.sid == sid:
                actions.extend(statement.expanded_actions)
                break
        return actions

    def get_resources_from_sid(self, sid):
        resources = []
        for statement in self.statements:
            if statement.sid == sid:
                resources.extend(statement.resources)
                break
        return resources

    def remove_actions_not_matching_these(self, actions_to_keep):
        # FIXME: is it still good here?
        for statement in self.statements:
            statement.remove_actions_not_matching_these(actions_to_keep)
        return self.json

    def remove_action_from_sid(self, sid, action):
        for statement in self.statements:
            if statement.sid == sid:
                statement.remove_action(action)

    @property
    def sids(self):
        these_sids = []
        for statement in self.statements:
            these_sids.append(statement.sid)
        return these_sids

    @property
    def json(self):
        """Return the Policy in JSON"""

        statements = []
        for statement in self.statements:
            this_statement = statement.expanded_json
            # If the value is not None
            if this_statement:
                statements.append(this_statement)
        self.policy = {"Version": POLICY_LANGUAGE_VERSION, "Statement": statements}
        return self.policy

    @property
    def original_json(self):
        return self.policy

    @property
    def all_allowed_actions(self):
        allowed_actions = []
        for statement in self.statements:
            allowed_actions.extend(statement.expanded_actions)
        allowed_actions = list(dict.fromkeys(allowed_actions))
        return allowed_actions

    @property
    def allows_privilege_escalation(self):
        """
        Determines whether or not the policy allows privilege escalation action combinations published by Rhino Security Labs.
        """
        escalations = []
        all_allowed_actions_lowercase = [x.lower() for x in self.all_allowed_actions]
        for key in PRIVILEGE_ESCALATION_METHODS:
            if set(PRIVILEGE_ESCALATION_METHODS[key]).issubset(all_allowed_actions_lowercase):
                escalation = {"type": key, "actions": PRIVILEGE_ESCALATION_METHODS[key]}
                escalations.append(escalation)
        return escalations

    @property
    def permissions_management_without_constraints(self):
        result = []
        for statement in self.statements:
            if statement.permissions_management_actions_without_constraints:
                result.extend(statement.permissions_management_actions_without_constraints)
        return result

    @property
    def write_actions_without_constraints(self):
        result = []
        for statement in self.statements:
            if statement.write_actions_without_constraints:
                result.extend(statement.write_actions_without_constraints)
        return result

    @property
    def tagging_actions_without_constraints(self):
        result = []
        for statement in self.statements:
            if statement.tagging_actions_without_constraints:
                result.extend(statement.write_actions_without_constraints)
        return result

    def allows_specific_actions_without_constraints(self, specific_actions):
        allowed = []
        if not isinstance(specific_actions, list):
            raise Exception("Please supply a list of actions.")

        # Doing this nested for loop so we can get results that use the official CamelCase actions, and
        # the results don't fail if given lowercase input.
        # this is less efficient but more accurate and the results are pretty :)
        for specific_action in specific_actions:
            for allowed_action in self.all_allowed_actions:
                if specific_action.lower() == allowed_action.lower():
                    allowed.append(allowed_action)
        return allowed

    @property
    def allows_data_leak_actions(self):
        return self.allows_specific_actions_without_constraints(READ_ONLY_DATA_LEAK_ACTIONS)


class StatementDetails:
    """
    Analyzes individual statements within a policy
    """

    def __init__(self, statement):
        self.statement = statement
        self.actions = self._actions()
        self.resources = self._resources()
        self.not_actions = []
        self.not_resources = []
        self.not_principal = []
        self.principal = []
        self.conditions = []
        self.effect = statement.get("Effect")
        self.sid = statement.get("Sid", "")

    def _actions(self):
        """Holds the actions in a statement"""
        actions = self.statement.get("Action")
        if not actions:
            return []
        if not isinstance(actions, list):
            actions = [actions]
        return actions

    def _resources(self):
        """Holds the resource ARNs in a statement"""
        resources = self.statement.get("Resource")
        if not resources:
            return []
        # If it's a string, turn it into a list
        if not isinstance(resources, list):
            resources = [resources]
        return resources

    def add_resource(self, resource):
        # Hack to see if the ARN is valid
        resource_type = get_resource_type_name_with_raw_arn(resource)
        logger.debug("Adding ARN type %s", resource_type)
        self.resources.append(resource)

    def remove_actions_not_matching_these(self, actions_to_keep):
        self.actions = self.expanded_actions
        lowercase_actions_to_keep = [x.lower() for x in actions_to_keep]
        actions_deleted = []
        placeholder_actions_list = []
        for action in self.actions:
            if action.lower() in lowercase_actions_to_keep:
                placeholder_actions_list.append(action)
            elif action.lower() not in lowercase_actions_to_keep:
                logger.debug("%s not found in list of actions to keep: %s", action.lower(), actions_to_keep)
                actions_deleted.append(action)
        self.actions.clear()
        self.actions.extend(placeholder_actions_list.copy())

    def remove_action(self, action_to_remove):
        self.actions = self.expanded_actions
        for this_action in self.actions:
            if action_to_remove.lower() == this_action.lower():
                logger.debug("Removing action %s" % this_action)
                self.actions.remove(this_action)

    @property
    def lowercase_expanded_actions(self):
        lowercase_actions = [x.lower() for x in self.expanded_actions]
        return lowercase_actions

    @property
    def json(self):
        if self.actions and self.resources:
            result = {
                "Sid": self.sid,
                "Effect": self.effect,
                "Action": self.actions,
                "Resource": self.resources
            }
        else:
            result = None
        return result

    @property
    def expanded_json(self):
        if self.actions and self.resources:
            result = {
                "Sid": self.sid,
                "Effect": self.effect,
                "Action": self.expanded_actions,
                "Resource": self.resources
            }
        else:
            result = None
        return result

    @property
    def has_resource_constraints(self):
        answer = True
        if len(self.resources) == 0:
            # This is probably a NotResources situation which we do not support.
            pass
        if len(self.resources) == 1:
            if self.resources[0] == "*":
                answer = False
        elif len(self.resources) > 1:
            # It's possible that someone writes a bad policy that includes both a resource ARN as well as a wildcard.
            for resource in self.resources:
                if resource == "*":
                    answer = False
        return answer

    @property
    def expanded_actions(self):
        expanded = determine_actions_to_expand(self.actions)
        return expanded

    # @property
    # def minimized_actions(self):
    #     minimized = minimize_statement_actions(
    #         self.actions, all_actions, minchars=0
    #     )
    #     self.actions = minimized
    #     return self.actions

    @property
    def effect_deny(self):
        if self.effect == "Deny":
            return True
        else:
            return False

    @property
    def effect_allow(self):
        if self.effect == "Allow":
            return True
        else:
            return False

    @property
    def services_in_use(self):
        service_prefixes = []
        for action in self.expanded_actions:
            service, action_name = action.split(":")
            if service not in service_prefixes:
                service_prefixes.append(service)
        service_prefixes.sort()
        return service_prefixes

    @property
    def permissions_management_actions_without_constraints(self):
        result = []
        if not self.has_resource_constraints:
            result = remove_actions_not_matching_access_level(self.expanded_actions, "Permissions management")
        return result

    @property
    def write_actions_without_constraints(self):
        result = []
        if not self.has_resource_constraints:
            result = remove_actions_not_matching_access_level(self.expanded_actions, "Write")
        return result

    @property
    def tagging_actions_without_constraints(self):
        result = []
        if not self.has_resource_constraints:
            result = remove_actions_not_matching_access_level(self.expanded_actions, "Tagging")
        return result

    @property
    def missing_resource_constraints(self):
        actions_missing_resource_constraints = []
        if len(self.resources) == 1:
            if self.resources[0] == "*":
                actions_missing_resource_constraints = remove_wildcard_only_actions(self.expanded_actions)
        return actions_missing_resource_constraints

    def missing_resource_constraints_for_modify_actions(self, always_look_for_actions=None):
        if always_look_for_actions is None:
            always_look_for_actions = []
        actions_missing_resource_constraints = self.missing_resource_constraints

        always_actions_found = []
        for action in actions_missing_resource_constraints:
            if action.lower() in [x.lower() for x in always_look_for_actions]:
                always_actions_found.append(action)
        modify_actions_missing_constraints = remove_read_level_actions(actions_missing_resource_constraints)
        modify_actions_missing_constraints = modify_actions_missing_constraints + always_actions_found
        return modify_actions_missing_constraints
