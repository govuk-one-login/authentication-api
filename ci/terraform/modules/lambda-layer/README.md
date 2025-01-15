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
| [aws_lambda_layer_version.lambda_layer](https://registry.terraform.io/providers/hashicorp/aws/5.75.1/docs/resources/lambda_layer_version) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_environment"></a> [environment](#input\_environment) | The environment this layer is for | `string` | n/a | yes |
| <a name="input_layer_name"></a> [layer\_name](#input\_layer\_name) | The name of the layer. var.environment will be prefixed to this name | `string` | n/a | yes |
| <a name="input_zip_file_path"></a> [zip\_file\_path](#input\_zip\_file\_path) | Location of the layer zip file on the local filesystem | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_arn"></a> [arn](#output\_arn) | n/a |
| <a name="output_layer_version"></a> [layer\_version](#output\_layer\_version) | n/a |
<!-- END_TF_DOCS -->
