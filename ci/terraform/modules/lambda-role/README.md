# Lambda Role

This module provisions a role, and attaches multiple IAM policies to it.
It is designed to be used to create the lambda role passed to a lambda via endpoint-module's
[lambda_role_arn](../endpoint-module/README.md#input_lambda_role_arn) input.

<!-- prettier-ignore-start -->
<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.9.8 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | 5.75.1 |
| <a name="requirement_local"></a> [local](#requirement\_local) | 2.5.2 |
| <a name="requirement_random"></a> [random](#requirement\_random) | 3.6.3 |
| <a name="requirement_time"></a> [time](#requirement\_time) | 0.12.1 |
| <a name="requirement_tls"></a> [tls](#requirement\_tls) | 4.0.6 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | 5.75.1 |

## Resources

| Name | Type |
|------|------|
| [aws_iam_policy.endpoint_xray_policy](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/resources/iam_policy) | resource |
| [aws_iam_policy.logging_policy](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/resources/iam_policy) | resource |
| [aws_iam_policy.networking_policy](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/resources/iam_policy) | resource |
| [aws_iam_role.lambda_role](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/resources/iam_role) | resource |
| [aws_iam_role_policy_attachment.endpoint_xray_policy_attachment](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.lambda_logs](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.networking_policy](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.provided_policies](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.provided_policies_count](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_policy_document.endpoint_xray_policy](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.lambda_can_assume_role](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/data-sources/iam_policy_document) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_environment"></a> [environment](#input\_environment) | n/a | `string` | n/a | yes |
| <a name="input_role_name"></a> [role\_name](#input\_role\_name) | n/a | `string` | n/a | yes |
| <a name="input_extra_tags"></a> [extra\_tags](#input\_extra\_tags) | Extra tags to apply to resources | `map(string)` | `{}` | no |
| <a name="input_policies_to_attach"></a> [policies\_to\_attach](#input\_policies\_to\_attach) | Policies to attach to the role | `list(string)` | `[]` | no |
| <a name="input_use_foreach_for_policies"></a> [use\_foreach\_for\_policies](#input\_use\_foreach\_for\_policies) | If true, use for\_each to attach policies to the role, otherwise use count. This is for migrating from count to for\_each. | `bool` | `false` | no |
| <a name="input_vpc_arn"></a> [vpc\_arn](#input\_vpc\_arn) | n/a | `string` | `""` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_arn"></a> [arn](#output\_arn) | n/a |
| <a name="output_name"></a> [name](#output\_name) | n/a |
<!-- END_TF_DOCS -->
<!-- prettier-ignore-end -->
