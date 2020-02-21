#!/usr/bin/env python3
"""
Parses the AWS HTML docs to create a YML file that understands the mapping between services and HTML files.
We store the HTML files in this manner so that the user can be more confident in the integrity of the data -
that it has not been altered in any way. The user can reproduce our steps with the original content at any time,
or update the HTML files on their own.
"""
import sys
import os
import csv
from pathlib import Path
sys.path.append(str(Path(os.path.dirname(__file__)).parent))
from policy_sentry.scraping.awsdocs import update_html_docs_directory, create_service_links_mapping_file, \
    get_list_of_service_prefixes_from_links_file
from policy_sentry.shared.constants import LINKS_YML_FILE_IN_PACKAGE, DEFAULT_ACCESS_OVERRIDES_FILE
from policy_sentry.shared.database import connect_db, create_database
from policy_sentry.shared.database import connect_db, ActionTable, ArnTable, ConditionTable

BUNDLED_DATABASE_FILE_PATH = str(Path(
    os.path.dirname(__file__)).parent) + '/policy_sentry/shared/data/' + 'aws.sqlite3'
BASE_DIR = str(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))


def build_database():
    print(BUNDLED_DATABASE_FILE_PATH)
    if os.path.exists(BUNDLED_DATABASE_FILE_PATH):
        os.remove(BUNDLED_DATABASE_FILE_PATH)
    db_session = connect_db(BUNDLED_DATABASE_FILE_PATH, initialization=True)
    all_aws_services = get_list_of_service_prefixes_from_links_file(
        LINKS_YML_FILE_IN_PACKAGE)
    create_database(db_session, all_aws_services, DEFAULT_ACCESS_OVERRIDES_FILE)


def update_docs():
    html_directory_path = str(Path(os.path.dirname(__file__)).parent) + '/policy_sentry/shared/data/docs/'
    links_yml_file = str(Path(os.path.dirname(__file__)).parent) + '/policy_sentry/shared/data/links.yml'
    print("Reminder: Run this from the main directory of the code repository.")
    print(f"Updating the HTML docs directory at {html_directory_path}.")
    update_html_docs_directory(html_directory_path)
    print("Creating the service links mapping file.")
    create_service_links_mapping_file(html_directory_path, links_yml_file)


# TODO: look for any commas, especially in the conditions list.
def write_action_table_csv(db_session):

    rows = db_session.query(ActionTable)
    f = open(os.path.join(BASE_DIR, 'policy_sentry/shared/data', 'action_table.csv'), 'w')
    out = csv.writer(f, delimiter=';')
    out.writerow([
        'service',
        'name',
        'description',
        'access_level',
        'resource_type_name',
        'resource_type_name_append_wildcard',
        'resource_arn_format']
    )
    for row in rows:
        # print(row)
        out.writerow([
            row.service,
            row.name,
            row.description,
            row.access_level,
            row.resource_type_name,
            row.resource_type_name_append_wildcard,
            row.resource_arn_format
        ])
        f.flush()
    f.close()


def write_arn_table_csv(db_session):
    rows = db_session.query(ArnTable)
    f = open(os.path.join(BASE_DIR, 'policy_sentry/shared/data', 'arn_table.csv'), 'w')
    out = csv.writer(f, delimiter=';')
    out.writerow([
        'resource_type_name',
        'raw_arn',
        'arn',
        'partition',
        'service',
        'region',
        'account',
        'resource_path',
        'condition_keys'
    ])
    for row in rows:
        out.writerow([
            row.resource_type_name,
            row.raw_arn,
            row.arn,
            row.partition,
            row.service,
            row.region,
            row.account,
            row.resource_path,
            row.condition_keys,
        ])
        f.flush()
    f.close()


def write_condition_table_csv(db_session):
    print()
    rows = db_session.query(ConditionTable)
    f = open(os.path.join(BASE_DIR, 'policy_sentry/shared/data', 'condition_table.csv'), 'w')
    out = csv.writer(f, delimiter=';')
    out.writerow([
        'service',
        'condition_key_name',
        'condition_key_service',
        'description',
        'condition_value_type',
    ])
    for row in rows:
        out.writerow([
            row.service,
            row.condition_key_name,
            row.condition_key_service,
            row.description,
            row.condition_value_type,
        ])
        f.flush()
    f.close()


def write_iam_database_to_csv():
    db_session = connect_db(BASE_DIR + '/policy_sentry/shared/data/aws.sqlite3')
    table_files = [
        os.path.join(BASE_DIR, 'policy_sentry/shared/data', 'action_table.csv'),
        os.path.join(BASE_DIR, 'policy_sentry/shared/data', 'arn_table.csv'),
        os.path.join(BASE_DIR, 'policy_sentry/shared/data', 'condition_table.csv')
    ]
    for table_file in table_files:
        if os.path.exists(table_file):
            os.remove(table_file)
    print("Writing Action Table to CSV...")
    write_action_table_csv(db_session)
    print("Writing ARN Table to CSV...")
    write_arn_table_csv(db_session)
    print("Writing Condition Table to CSV...")
    write_condition_table_csv(db_session)


if __name__ == '__main__':
    print("Downloading the latest AWS documentation from the Actions, Resources, and Condition Keys page")
    update_docs()
    print("Building the IAM SQLite3 database")
    build_database()
    print("Exporting the IAM database to CSV")
    write_iam_database_to_csv()

