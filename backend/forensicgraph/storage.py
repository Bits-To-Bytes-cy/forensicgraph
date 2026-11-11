"""Restricted object-storage abstraction for original evidence and derivatives."""

from __future__ import annotations

from collections.abc import Iterator
from io import BufferedReader
from pathlib import Path
from typing import Protocol

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

from forensicgraph.config import settings


class ObjectStorage(Protocol):
    def put_file(self, key: str, path: Path, content_type: str) -> None: ...

    def copy(self, source_key: str, destination_key: str) -> None: ...

    def exists(self, key: str) -> bool: ...

    def read(self, key: str) -> Iterator[bytes]: ...

    def delete(self, key: str) -> None: ...


class MinioStorage:
    """S3-compatible storage with a fixed, application-owned bucket."""

    def __init__(self) -> None:
        endpoint = settings.minio_endpoint.rstrip("/")
        self.client = boto3.client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id=settings.minio_access_key,
            aws_secret_access_key=settings.minio_secret_key,
            config=Config(signature_version="s3v4"),
            region_name="us-east-1",
        )
        self.bucket = settings.minio_bucket

    def ensure_bucket(self) -> None:
        try:
            self.client.head_bucket(Bucket=self.bucket)
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") not in {
                "404",
                "NoSuchBucket",
            }:
                raise
            self.client.create_bucket(Bucket=self.bucket)

    def put_file(self, key: str, path: Path, content_type: str) -> None:
        self.ensure_bucket()
        with path.open("rb") as stream:
            self.client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=stream,
                ContentType=content_type,
                Metadata={"forensicgraph-managed": "true"},
            )

    def copy(self, source_key: str, destination_key: str) -> None:
        self.ensure_bucket()
        self.client.copy_object(
            Bucket=self.bucket,
            CopySource={"Bucket": self.bucket, "Key": source_key},
            Key=destination_key,
            MetadataDirective="COPY",
        )

    def exists(self, key: str) -> bool:
        try:
            self.client.head_object(Bucket=self.bucket, Key=key)
            return True
        except self.client.exceptions.ClientError as error:
            if error.response.get("Error", {}).get("Code") in {"404", "NoSuchKey"}:
                return False
            raise

    def read(self, key: str) -> Iterator[bytes]:
        response = self.client.get_object(Bucket=self.bucket, Key=key)
        body: BufferedReader = response["Body"]
        try:
            while chunk := body.read(1024 * 1024):
                yield chunk
        finally:
            body.close()

    def delete(self, key: str) -> None:
        self.client.delete_object(Bucket=self.bucket, Key=key)


def get_storage() -> ObjectStorage:
    return MinioStorage()
