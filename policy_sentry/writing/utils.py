"""Some utils used for writing policies; not significant enough to add to query functions."""
import logging
from policy_sentry.querying.actions import get_action_data, remove_actions_not_matching_access_level
from policy_sentry.querying.all import get_all_service_prefixes

all_service_prefixes = get_all_service_prefixes()
logger = logging.getLogger(__name__)


def remove_wildcard_only_actions(actions_list):
    """Given a list of actions, remove the ones that CANNOT be restricted to ARNs, leaving only the ones that CAN."""
    actions_list_unique = list(dict.fromkeys(actions_list))
    results = []
    for action in actions_list_unique:
        service_prefix, action_name = action.split(":")
        if service_prefix not in all_service_prefixes:
            continue
        action_data = get_action_data(service_prefix, action_name)

        if len(action_data[service_prefix]) == 0:
            pass
        elif len(action_data[service_prefix]) == 1:
            if action_data[service_prefix][0]["resource_arn_format"] == "*":
                pass
            else:
                # Let's return the CamelCase action name format
                results.append(action_data[service_prefix][0]["action"])
        else:
            results.append(action_data[service_prefix][0]["action"])
    return results


def remove_read_level_actions(actions_list):
    """Given a set of actions, return that list of actions,
    but only with actions at the 'Write', 'Tagging', or 'Permissions management' levels"""
    write_actions = remove_actions_not_matching_access_level(actions_list, "Write")
    permissions_management_actions = remove_actions_not_matching_access_level(actions_list, "Permissions management")
    tagging_actions = remove_actions_not_matching_access_level(actions_list, "Tagging")
    modify_actions = tagging_actions + write_actions + permissions_management_actions
    return modify_actions
