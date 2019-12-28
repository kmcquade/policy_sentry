"""
The same as ArnActionGroup, but with things broken out into separate functions so it makes more sense.
We want to avoid the phenomenon where so many things are being modified in-place that it becomes impossible
to understand what is going on.
"""
import re
import copy
import sys
from sqlalchemy import and_
from policy_sentry.shared.database import ActionTable, ArnTable
from policy_sentry.shared.arns import get_service_from_arn, does_arn_match
from policy_sentry.shared.actions import get_action_name_from_action, get_service_from_action
from policy_sentry.shared.query import remove_actions_that_are_not_wildcard_arn_only


# from policy_sentry.shared.query import remove_actions_that_are_not_wildcard_arn_only


class PolicyCollection:
    """
    This class is critical to the creation of least privilege policies.
    It uses the SIDs as namespaces. The namespaces follow this format:
        {Servicename}{Accesslevel}{Resourcetypename}

    The object will look like this:

    arns = [
        {
          'arn': 'arn:aws:s3:::example-org-flow-logs',
          'service': 's3'
          'access_level': 'List',
          'arn_format': 'arn:${Partition}:s3:::${BucketName}',
          'actions': [
            's3:ListBucket'
          ]
        }
    ]
    """

    def __init__(self):
        self.arns = []

    def add_crud_entry(self, db_session, arn_list_from_user, access_level):
        # TODO: Change 'arn_list_from_user' to 'list_of_arns'
        for arn_from_user in arn_list_from_user:
            service = get_service_from_arn(arn_from_user)
            # Query the SQLite database for actions that match the provided service prefix
            for row in db_session.query(ActionTable).filter(ActionTable.service.like(service)):
                # row.resource_arn_format = arn:${Partition}:s3:::${BucketName}
                if does_arn_match(arn_from_user, row.resource_arn_format):
                    if row.access_level == access_level:  # access_level = "List"
                        actions_list = get_actions_matching_arn_format_and_access_level(db_session, row.resource_arn_format, access_level)
                        temp_arn_dict = {
                            'arn': arn_from_user,  # arn:aws:s3:::example-org-flow-logs
                            'service': service,  # s3
                            'access_level': access_level,  # List
                            'arn_format': row.resource_arn_format,  # arn:${Partition}:s3:::${BucketName}
                            'actions': actions_list
                        }

                        if temp_arn_dict in self.arns:
                            continue
                        self.arns.append(copy.deepcopy(temp_arn_dict))

    # pylint: disable=too-many-arguments
    def add_complete_entry(
            self,
            arn_from_user,  # arn:aws:s3:::example-org-flow-logs
            service,  # s3
            access_level,  # List
            raw_arn_format,  # arn:${Partition}:s3:::${BucketName}
            actions_list):  # ['s3:ListBucket'
        """
        Add a single entry with all the necessary fields filled out.
        :param arn_from_user:
        :param service:
        :param access_level:
        :param raw_arn_format:
        :param actions_list:
        """
        temp_arn_dict = {
            'arn': arn_from_user,
            'service': service,
            'access_level': access_level,
            'arn_format': raw_arn_format,
            'actions': actions_list
        }
        # If there is already an entry, skip it to avoid duplicates
        # Otherwise, add it
        if temp_arn_dict in self.arns:
            pass
        else:
            self.arns.append(copy.deepcopy(temp_arn_dict))

    def update_actions_for_raw_arn_format_in_place(self, db_session):
        for i in range(len(self.arns)):
            actions_list = get_actions_matching_arn_format_and_access_level(
                db_session,
                self.arns[i]['arn_format'],
                self.arns[i]['access_level']
            )
            # TODO: Since this will result in duplicates, it needs to be cleaned of duplicates
            # TODO: Try out the following:
            # for action in actions_list:
            #     if action not in self.arns[i]['actions']:
            #         self.arns[i]['actions'].append(action)
            self.arns[i]['actions'].append(actions_list)

    def get_arns(self):
        """
        Getter function for the ARNs object
        :return: ARNs object
        """
        return self.arns

    def does_action_exist(self, action):
        """
        Get boolean response for whether or not an action exists under any of the ARNs.
        :param action: full action name, like s3:GetObject
        :return: True or False
        """
        exists = 0
        for i in range(len(self.arns)):
            if action in self.arns[i]['actions']:
                exists = exists + 1
            else:
                continue
        return exists > 0

    def get_policy_elements(self, db_session):
        """
        :param db_session: database session.
        :return: arn_dict. This is a dictionary of dictionaries. Each sub-dictionary has the following elements:
          1. name: The SID namespace. This follows the format of {Servicename} + {Accesslevel} + {Resourcetypename}.
          2. actions: A list of actions
          3. arns: A list of resource ARNs that fall under this namespace.

        Example:
        arn_dict = {
            'S3ReadBucket': {
                'name': 'S3ListBucket',
                'actions': ['s3:listbucket'],
                'arns': ['arn:aws:s3:::example-org-flow-logs']
            },
            'KmsReadKmskey': {
                'name': 'KmsReadKmskey',
                'actions': [
                    'kms:describekey', 'kms:getkeypolicy', 'kms:getkeyrotationstatus',
                    'kms:getparametersforimport', 'kms:getpublickey', 'kms:listresourcetags'
                ]
                'arns': ['arn:aws:kms:us-east-1:123456789012:key/123456']
            }
        }
        """
        arn_dict = {}
        for i in range(len(self.arns)):
            # Create SID Namespace
            query_resource_arn_format = db_session.query(
                ArnTable.resource_type_name).filter(ArnTable.raw_arn.like(self.arns[i]['arn_format']))
            resource_arn_format = query_resource_arn_format.first()
            temp_name = create_policy_sid_namespace(
                self.arns[i]['service'],
                self.arns[i]['access_level'],
                str(resource_arn_format)
            )
            temp_actions_list = []
            temp_actions_list.extend(self.arns[i]['actions'])
            temp_arns_list = []
            temp_arns_list.append(self.arns[i]['arn'])

            thing = {
                'name': temp_name,
                'actions': copy.deepcopy(temp_actions_list),
                'arns': copy.deepcopy(temp_arns_list)
            }
            # thing = {'name':'namespace', 'actions':'actions_list', 'arns':'arns_list'} for self.arns[i]['arn_format']
            # If raw_arn is also in the list
            # If access_level is also in the list
            if temp_name in arn_dict:
                arn_dict[temp_name]['arns'].extend(temp_arns_list)
            else:
                arn_dict[temp_name] = copy.deepcopy(thing)
        return arn_dict

    def remove_actions_duplicated_in_wildcard_resources(self):
        """
        Removes actions from the object that are in a resource-specific ARN, as well as the `*` resource.
        For example, if ssm:GetParameter is restricted to a specific parameter path, as well as `*`, then we want to
        remove the `*` option to force least privilege.
        """
        actions_under_wildcard_resources = []
        actions_under_wildcard_resources_to_nuke = []
        for i in range(len(self.arns)):
            if self.arns[i]['arn_format'] == '*':
                actions_under_wildcard_resources.extend(
                    self.arns[i]['actions'])
        # Now that we have the list of actions that are under the * ARN,
        # let's see if that action exists under other SIDs
        if len(actions_under_wildcard_resources) > 0:
            for i in range(len(self.arns)):
                if '*' not in self.arns[i]['arn_format']:
                    for j in actions_under_wildcard_resources:
                        if actions_under_wildcard_resources[j] in self.arns[i]['actions']:
                            actions_under_wildcard_resources_to_nuke.append(
                                actions_under_wildcard_resources[j])
        if len(actions_under_wildcard_resources_to_nuke) > 0:
            for i in range(len(self.arns)):
                if '*' in self.arns[i]['arn_format']:
                    for j in actions_under_wildcard_resources_to_nuke:
                        try:
                            self.arns[i]['actions'].remove(
                                str(actions_under_wildcard_resources_to_nuke[j]))
                        except BaseException:  # pylint: disable=broad-except
                            print("Removal not successful")

    def remove_actions_not_matching_list(self, actions_list):
        """
        :param actions_list: List of actions to leave. All actions not in this list are removed
        :return: Nothing
        """
        for i in range(len(self.arns)):
            placeholder_actions_list = []
            for action in range(len(self.arns[i]['actions'])):
                # If the action in self.arns is not in the list of selected actions,
                # don't copy it to the placeholder
                if self.arns[i]['actions'][action] not in actions_list:
                    pass
                # If it is in the list of selected actions, append it to the
                # placeholder
                else:
                    placeholder_actions_list.append(
                        self.arns[i]['actions'][action])
            # Clear the list and then extend it to include the updated actions
            # only
            self.arns[i]['actions'].clear()
            self.arns[i]['actions'].extend(placeholder_actions_list.copy())

        self.remove_sids_with_empty_action_lists()

    def remove_sids_with_empty_action_lists(self):
        """
        Now that we've removed a bunch of actions, if there are SID groups without any actions,
            remove them so we don't get SIDs with empty action lists
        """
        indexes_to_delete = []
        for i in range(len(self.arns)):
            if len(self.arns[i]['actions']) > 0:
                pass
            # If the size is zero, add it to the indexes_to_delete list.
            else:
                indexes_to_delete.append(i)
        # Loop through indexes_to_delete in reverse order (so we delete index
        # 10 before index 8, for example)
        if len(indexes_to_delete) > 0:
            for i in reversed(range(len(indexes_to_delete))):
                del self.arns[indexes_to_delete[i]]
                # except ValueError as e:
                #     if 'list.remove(x)' in str(e):
                #         print("Action is " + self.arns[i]['actions'][action])
                #         print("actions_list is" + str(actions_list))

    def combine_policy_elements(self):
        """
        Consolidate the policy elements by looking at where ARNs are used
        :return:
        """
        # Using numbers in the 'altered' list to identify indexes that have
        # been altered
        altered = []
        for i in range(len(self.arns)):
            for j in range(len(self.arns)):
                if i == j:
                    continue
                # If the ARN also has other occurrences, get the value of those
                # occurrences and copy it over
                if self.arns[i]['arn_format'] == self.arns[j]['arn_format'] and len(
                        self.arns[i]['actions']) > 0 and i not in altered:
                    self.arns[i]['actions'].extend(self.arns[j]['actions'])
                    self.arns[j]['actions'].clear()
                    altered.append(i)

        self.remove_sids_with_empty_action_lists()
        self.remove_actions_duplicated_in_wildcard_resources()


def get_actions_matching_arn_format_and_access_level(db_session, arn_format, access_level):
    """
    Given arn_format and access_level, return the full list of actions
    :param db_session: SQLAlchemy database session
    :param access_level: "List"
    :param arn_format: "arn:${Partition}:s3:::${BucketName}"
    """
    actions_list = []
    for row in db_session.query(ActionTable).filter(and_(ActionTable.access_level.like(access_level)), ActionTable.resource_arn_format.like(arn_format)):
        if access_level == row.access_level and arn_format == row.resource_arn_format:
            actions_list.append(f"{row.service}:{row.name}")
    return actions_list


def process_crud_cfg(policy_collection_obj, cfg, db_session):
    """
    basically process_resource_specific_acls, but without the stuff at the end. instead it just returns a list
    """
    try:
        for category in cfg:
            if category == 'roles_with_crud_levels':
                for principal in cfg[category]:
                    # TODO: Figure out "if 'wildcard' in principal.keys()"
                    if 'wildcard' in principal.keys():
                        if principal['wildcard'] is not None:
                            if isinstance(principal['wildcard'], list):
                                verified_wildcard_actions = remove_actions_that_are_not_wildcard_arn_only(
                                    db_session, principal['wildcard'])
                                if len(verified_wildcard_actions) > 0:
                                    policy_collection_obj.process_list_of_actions(
                                        verified_wildcard_actions, db_session)
                    if 'read' in principal.keys():
                        if principal['read'] is not None:
                            policy_collection_obj.add_crud_entry(db_session, principal['read'], "Read")
                    if 'write' in principal.keys():
                        if principal['write'] is not None:
                            policy_collection_obj.add_crud_entry(db_session, principal['write'], "Write")
                    if 'list' in principal.keys():
                        if principal['list'] is not None:
                            policy_collection_obj.add_crud_entry(db_session, principal['list'], "List")
                    if 'permissions-management' in principal.keys():
                        if principal['permissions-management'] is not None:
                            policy_collection_obj.add_crud_entry(db_session, principal['permissions-management'], "Permissions management")
                    if 'tag' in principal.keys():
                        if principal['tag'] is not None:
                            policy_collection_obj.add_crud_entry(db_session, principal['tag'], "Tagging")

    except IndexError:
        print("IndexError: list index out of range. This is likely due to an ARN in your list equaling ''. "
              "Please evaluate your YML file and try again.")
        sys.exit()
    arn_dict = policy_collection_obj.get_policy_elements(db_session)
    return arn_dict


def process_actions_cfg(supplied_actions, db_session):
    policy_collection = PolicyCollection()
    arns_matching_supplied_actions = []

    for action in supplied_actions:
        action_name = get_action_name_from_action(action)
        service_name = get_service_from_action(action)
        for row in db_session.query(ActionTable).filter(and_(ActionTable.service.like(service_name),
                                                             ActionTable.name.like(action_name))):
            if row.resource_arn_format not in arns_matching_supplied_actions:
                arns_matching_supplied_actions.append(
                    [row.resource_arn_format, row.access_level, str(row.service + ':' + row.name)])
    # Identify the actions that require wildcard ONLY - i.e., they do not permit use of resource ARNs
    # If that's the case, add it to the wildcard namespace. Otherwise, don't add it.
    actions_with_wildcard = []
    for i in range(len(arns_matching_supplied_actions)):
        if '*' not in arns_matching_supplied_actions[i][0]:
            policy_collection.add_crud_entry(db_session, [arns_matching_supplied_actions[i][0]],
                     arns_matching_supplied_actions[i][1])
        else:
            actions_with_wildcard.append(
                arns_matching_supplied_actions[i][2])
    # TODO: Fix the cleanup functions so they are more straightforward
    # Remove actions from the collection that have the same CRUD level but were not requested by the user
    policy_collection.update_actions_for_raw_arn_format_in_place(db_session)
    # If the action exists in the wildcard list, remove it from the collection so we don't have actions across both
    policy_collection.remove_actions_not_matching_list(supplied_actions)

    actions_with_wildcard_placeholder = []
    for action in range(len(actions_with_wildcard)):
        if policy_collection.does_action_exist(actions_with_wildcard[action]):
            pass
        else:
            actions_with_wildcard_placeholder.append(
                actions_with_wildcard[action])

    actions_with_wildcard.clear()
    actions_with_wildcard.extend(actions_with_wildcard_placeholder)
    policy_collection.combine_policy_elements()
    policy_collection.remove_actions_duplicated_in_wildcard_resources()
    # If the wildcard list is not empty
    if len(actions_with_wildcard) > 0:
        policy_collection.add_complete_entry(
            '*', 'Mult', 'Mult', '*', actions_with_wildcard)
    arn_dict = policy_collection.get_policy_elements(db_session)
    return arn_dict


def create_policy_sid_namespace(service, access_level, resource_type_name):
    """
    Description: Simply generates the SID name. The SID groups ARN types that share an access level.
    For example, S3 objects vs. SSM Parameter have different ARN types - as do S3 objects vs S3 buckets.
    That's how we choose to group them.

    :param service: "ssm"
    :param access_level: "Read"
    :param resource_type_name: "parameter"
    :return: SsmReadParameter
    """
    # Sanitize the resource_type_name; otherwise we hit some list conversion
    # errors
    resource_type_name = re.sub('[^A-Za-z0-9]+', '', resource_type_name)
    # Also remove the space from the Access level, if applicable. This only
    # applies for "Permissions management"
    access_level = re.sub('[^A-Za-z0-9]+', '', access_level)
    sid_namespace = capitalize_first_character(service) + capitalize_first_character(
        access_level) + capitalize_first_character(resource_type_name)
    return sid_namespace


def capitalize_first_character(some_string):
    """
    Description: Capitalizes the first character of a string
    :param some_string:
    :return:
    """
    return ' '.join(''.join([w[0].upper(), w[1:].lower()])
                    for w in some_string.split())
