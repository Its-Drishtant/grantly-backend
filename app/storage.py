"""Private storage. Local disk for development, S3-compatible object storage when configured."""
import os
from pathlib import Path
import boto3

def configured(): return bool(os.getenv('S3_BUCKET'))
def client():
    return boto3.client('s3',endpoint_url=os.getenv('S3_ENDPOINT_URL') or None,region_name=os.getenv('AWS_DEFAULT_REGION','ap-south-1'))
def put(key: str, content: bytes, mime: str, root: Path):
    if configured():
        client().put_object(Bucket=os.environ['S3_BUCKET'],Key=key,Body=content,ContentType=mime,ServerSideEncryption='AES256')
    else: (root/key).write_bytes(content)
def signed_download(key: str, name: str):
    safe_name=''.join(c for c in name if c.isalnum() or c in ' ._-') or 'document'
    return client().generate_presigned_url('get_object',Params={'Bucket':os.environ['S3_BUCKET'],'Key':key,'ResponseContentDisposition':f'attachment; filename="{safe_name}"'},ExpiresIn=60)
def delete(key: str, root: Path):
    if configured(): client().delete_object(Bucket=os.environ['S3_BUCKET'],Key=key)
    else: (root/key).unlink(missing_ok=True)
