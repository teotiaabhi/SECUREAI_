# Test: negative for rule SEC-001
# Expected: should_not_trigger
# Category: secrets
# Language: python

"""
S3 backup utility for production data exports.
All credentials are loaded from environment variables at runtime.
"""

import os
import sys
import gzip
import logging
from datetime import datetime

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger(__name__)

# Load AWS credentials from environment variables
AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
BACKUP_BUCKET = os.environ.get('BACKUP_BUCKET', 'company-prod-db-backups')


def _validate_credentials():
    """Ensure required environment variables are set before proceeding."""
    if not AWS_ACCESS_KEY_ID or not AWS_SECRET_ACCESS_KEY:
        raise EnvironmentError(
            "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set as environment variables."
        )


def get_s3_client():
    """Create an S3 client using credentials sourced from the environment."""
    _validate_credentials()
    return boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION,
    )


def upload_backup(file_path: str) -> str:
    """Compress and upload a database dump file to S3."""
    s3 = get_s3_client()
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    object_key = f"backups/{timestamp}/{os.path.basename(file_path)}.gz"

    compressed_path = file_path + '.gz'
    with open(file_path, 'rb') as f_in, gzip.open(compressed_path, 'wb') as f_out:
        f_out.writelines(f_in)

    try:
        s3.upload_file(compressed_path, BACKUP_BUCKET, object_key)
        logger.info("Uploaded %s to s3://%s/%s", file_path, BACKUP_BUCKET, object_key)
    except NoCredentialsError:
        logger.error("AWS credentials not found in environment")
        raise
    except ClientError as exc:
        logger.error("Upload failed: %s", exc)
        raise
    finally:
        os.remove(compressed_path)

    return f"s3://{BACKUP_BUCKET}/{object_key}"


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python negative_01_env_vars.py <dump_file>")
        sys.exit(1)
    url = upload_backup(sys.argv[1])
    print(f"Backup uploaded: {url}")
