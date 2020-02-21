Cheat sheet
-------------------

Commands
~~~~~~~~

*
  ``create-template``\ : Creates the YML file templates for use in the ``write-policy`` command types.

*
  ``write-policy``\ : Leverage a YAML file to write policies for you


  * Option 1: CRUD Mode. Specify CRUD levels (Read, Write, List, Tagging, or Permissions management) and the ARN of the resource. It will write this for you. See the documentation for more details.
  * Option 2: Actions Mode. Specify a list of actions. It will write the IAM Policy for you, but you will have to fill in the ARNs. See the documentation for more details.

*
  ``write-policy-dir``\ : This can be helpful in writing batches of JSON policy files at a time.


* ``query``: Query the IAM database tables. This can help when filling out the Policy Sentry templates, or just querying the database for quick knowledge.

  * Option 1: Query the Actions Table (``action-table``)
  * Option 2: Query the ARNs Table (``arn-table``)
  * Option 3: Query the Conditions Table (``condition-table``)

*
  ``initialize``\ : (Optional) Create a SQLite database that contains all of the services available through the `Actions, Resources, and Condition Keys documentation <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_actions-resources-contextkeys.html>`__. See the `documentation <./initialize.html>`__.



Policy Writing Commands
~~~~~~~~~~~~~~~~~~~~~~~
.. code-block:: bash

    # Create templates first!!! This way you can just paste the values you need rather than remembering the YAML format
    # CRUD mode
    policy_sentry create-template --name myRole --output-file tmp.yml --template-type crud
    # Actions mode
    policy_sentry create-template --name myRole --output-file tmp.yml --template-type actions

    # Get a list of actions that do not support resource constraints
    policy_sentry query action-table --service s3 --wildcard-only --fmt yaml

    # Get a list of actions at the "Write" level in S3 that do not support resource constraints
    policy_sentry query action-table --service s3 --access-level write --wildcard-only --fmt yaml

    # Initialize the policy_sentry config folder and create the IAM database tables.
    policy_sentry initialize

    # Write policy based on resource-specific access levels
    policy_sentry write-policy --input-file examples/yml/crud.yml

    # Write policy_sentry YML files based on resource-specific access levels on a directory basis
    policy_sentry write-policy-dir --input-dir examples/input-dir --output-dir examples/output-dir

    # Write policy based on a list of actions
    policy_sentry write-policy --input-file examples/yml/actions.yml


IAM Database Query Commands
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Query the **Action**\  table:

.. code-block:: bash

    # Get a list of all IAM actions across ALL services that have "Permissions management" access
    policy_sentry query action-table --service all --access-level permissions-management

    # Get a list of all IAM Actions available to the RAM service
    policy_sentry query action-table --service ram

    # Get details about the `ram:TagResource` IAM Action
    policy_sentry query action-table --service ram --name tagresource

    # Get a list of all IAM actions under the RAM service that have the Permissions management access level.
    policy_sentry query action-table --service ram --access-level permissions-management

    # Get a list of all IAM actions under the SES service that support the `ses:FeedbackAddress` condition key.
    policy_sentry query action-table --service ses --condition ses:FeedbackAddress

* Query the **ARN**\  table:

.. code-block:: bash

    # Get a list of all RAW ARN formats available through the SSM service.
    policy_sentry query arn-table --service ssm

    # Get the raw ARN format for the `cloud9` ARN with the short name `environment`
    policy_sentry query arn-table --service cloud9 --name environment

    # Get key/value pairs of all RAW ARN formats plus their short names
    policy_sentry query arn-table --service cloud9 --list-arn-types

* Query the **Condition Keys**\  table:

.. code-block:: bash

    # Get a list of all condition keys available to the Cloud9 service
    policy_sentry query condition-table --service cloud9
    # Get details on the condition key titled `cloud9:Permissions`
    policy_sentry query condition-table --service cloud9 --name cloud9:Permissions


Initialization (Optional)
~~~~~~~~~~~~~~~~~~~~~~~~~
.. code-block:: bash

    # Initialize the policy_sentry config folder and create the IAM database tables.
    policy_sentry initialize

    # Fetch the most recent version of the AWS documentation so you can experiment with new services.
    policy_sentry initialize --fetch

    # Override the Access Levels by specifying your own Access Levels (example:, correcting Permissions management levels)
    policy_sentry initialize --access-level-overrides-file ~/.policy_sentry/access-level-overrides.yml
    policy_sentry initialize --access-level-overrides-file ~/.policy_sentry/overrides-resource-policies.yml
