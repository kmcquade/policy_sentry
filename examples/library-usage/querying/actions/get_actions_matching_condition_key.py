#!/usr/bin/env python
from policy_sentry.shared.database import connect_db
from policy_sentry.querying.actions import get_actions_matching_condition_key


if __name__ == '__main__':
    db_session = connect_db('bundled')
    output = get_actions_matching_condition_key(db_session, "ses", "ses:FeedbackAddress")
    print(output)

"""
Output:

[
    'ses:sendemail',
    'ses:sendbulktemplatedemail',
    'ses:sendcustomverificationemail',
    'ses:sendemail',
    'ses:sendrawemail',
    'ses:sendtemplatedemail'
]
"""
