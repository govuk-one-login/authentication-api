#!/usr/bin/env bash

SOURCE=/dev/stdin
ACCOUNT=digital-identity-prod

function usage() {
  cat <<USAGE
  A script to replay audit events from cold storage to the fraud queue via an S3 bucket.
  Expects a list of S3 URLs point at the source files (in cold storage) to replay.

  Usage:
    $0 -d <desination s3 url> [-f <filename>]

  Options:
    -d   the destination s3 url e.g. s3://replay-bucket/
    -a   the gds cli account alias to use to authenticate to AWS. Defaults to digital-identity-prod.
    -f   the name of the file to read the list of files from. Defaults to stdin.
USAGE
}

if [[ $# == 0 ]]; then
  usage
fi
while [[ $# -gt 0 ]]; do
  case $1 in
    -f)
      shift
      SOURCE=$1
      ;;
    -d)
      shift
      DESTINATION=$1
      ;;
    -a)
      shift
      ACCOUNT=$1
      ;;
    *)
      usage
      exit 1
      ;;
  esac
  shift
done

while read f; do
  gds aws "${ACCOUNT}" -- aws s3 cp "${f}" "${DESTINATION}"
done < "${SOURCE}"
