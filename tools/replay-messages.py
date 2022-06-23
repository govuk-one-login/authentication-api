#!/usr/bin/env python3

import boto3
import sys
import argparse


def copy_file(source, destination, s3_client):
    source_parts = source.split("/")
    source_bucket = source_parts[0]
    source_key = "/".join(source_parts[1:])
    destination_key = source_parts[-1]

    print("Copying bucket = {} key = {} to bucket = {} key = {} ... ".format(source_bucket, source_key, destination, destination_key), end="")

    s3_client.copy_object(Bucket=destination,
                          CopySource=source,
                          Key=destination_key,
                          ServerSideEncryption="AES256")

    print(f"done!\n")


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Copy files from one S3 bucket to another to enable replay')
    parser.add_argument("-d", "--destination", metavar="destination", required=True, help="The name of the destination bucket")

    args = parser.parse_args()

    s3_client = boto3.client('s3')

    files = []
    for line in sys.stdin:
        files.append(line.strip())

    print("{:d} files to copy!".format(len(files)))

    s3_client.list_objects(Bucket="production-fraud-replay-bucket")

    for file in files:
        copy_file(file,args.destination, s3_client)
