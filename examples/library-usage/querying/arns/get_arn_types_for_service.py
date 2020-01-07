#!/usr/bin/env python
from policy_sentry.shared.database import connect_db
from policy_sentry.querying.arns import get_arn_types_for_service


if __name__ == '__main__':
    db_session = connect_db('bundled')
    output = get_arn_types_for_service(db_session, "s3")
    print(output)

"""
Output:

{
    "accesspoint": "arn:${Partition}:s3:${Region}:${Account}:accesspoint/${AccessPointName}",
    "bucket": "arn:${Partition}:s3:::${BucketName}",
    "object": "arn:${Partition}:s3:::${BucketName}/${ObjectName}",
    "job": "arn:${Partition}:s3:${Region}:${Account}:job/${JobId}",
}
"""
