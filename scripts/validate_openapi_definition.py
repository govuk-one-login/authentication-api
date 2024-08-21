#!/usr/bin/env python3
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("pyyaml is not installed. Please install it using `pip3 install pyyaml`")
    exit(1)

openapi_definition_file: Path = Path(sys.argv[1]).absolute()
try:
    assert openapi_definition_file.exists(), f"{openapi_definition_file} does not exist"
    assert openapi_definition_file.is_file(), f"{openapi_definition_file} is not a file"
except AssertionError as e:
    print(e)
    exit(1)

openapi_definition: dict = None
try:
    openapi_definition = yaml.safe_load(
        openapi_definition_file.read_text(encoding="utf-8")
    )
except yaml.YAMLError as e:
    print(f"Error parsing {openapi_definition_file}: {e}")
    exit(1)

print(f"Validating OpenAPI definition: {openapi_definition_file}")

for endpoint_name, methods in openapi_definition["paths"].items():
    for method_name, method_definition in methods.items():
        try:
            # Check if the method definition has x-amazon-apigateway-integration
            assert (
                "x-amazon-apigateway-integration" in method_definition
            ), f"Missing x-amazon-apigateway-integration for {method_name} {endpoint_name}"

            api_integration = method_definition["x-amazon-apigateway-integration"]

            # Check if the x-amazon-apigateway-integration has type and it is
            # aws_proxy
            assert (
                "type" in api_integration
            ), f"Missing type in x-amazon-apigateway-integration for {method_name} {endpoint_name}"
            assert (
                api_integration["type"] == "aws_proxy"
            ), f"type in x-amazon-apigateway-integration for {method_name} {endpoint_name} is not aws_proxy"

            # Check if the x-amazon-apigateway-integration has uri and uri is
            # a terraform template variable
            assert (
                "uri" in api_integration
            ), f"Missing uri in x-amazon-apigateway-integration for {method_name} {endpoint_name}"
            assert (
                re.search(r"\${.*}", api_integration["uri"]) is not None
            ), f"uri in x-amazon-apigateway-integration for {method_name} {endpoint_name} is not a terraform template variable"

            # Check if the x-amazon-apigateway-integration has httpMethod and
            # it is POST
            assert (
                "httpMethod" in api_integration
            ), f"Missing httpMethod in x-amazon-apigateway-integration for {method_name} {endpoint_name}"
            assert (
                api_integration["httpMethod"] == "POST"
            ), f"httpMethod in x-amazon-apigateway-integration for {method_name} {endpoint_name} is not POST"

            # Check if the x-amazon-apigateway-integration has timeoutInMillis
            # and it is an integer (50 <= x <= 2900)
            assert (
                "timeoutInMillis" in api_integration
            ), f"Missing timeoutInMillis in x-amazon-apigateway-integration for {method_name} {endpoint_name}"
            assert (
                isinstance(api_integration["timeoutInMillis"], int)
                and 50 <= api_integration["timeoutInMillis"] <= 29000
            ), f"timeoutInMillis in x-amazon-apigateway-integration for {method_name} {endpoint_name} is not an integer between 50 and 29000"
        except AssertionError as e:
            print(f"  {e}")
            exit(1)
            exit(1)

print("OpenAPI definition is valid")
