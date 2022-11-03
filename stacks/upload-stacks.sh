#!/bin/sh
aws s3 cp . s3://di-auth-stacks --recursive --exclude '*' --include '*.yaml'
