# Manual stacks - TxMA

## Intro

The CloudFormation template sets up all the infrastructure for integration with TxMA.

This Stack is deployed manually once per account/environment.

## Deployment

To deploy the template to the appropriate AWS account, ensure you are at the root of the project.

Replace `<environment>` with `dev`, `build`, `staging`, `integration`, `production` in either of the commands below.

### Creating a New Stack

Set your AWS profile to the correct environment, then run `export ENVIRONMENT=<environment>`, then run:

```bash
aws cloudformation create-stack --stack-name txma \
  --template-body file://$(pwd)/template.yml \
  --region eu-west-2 \
  --parameters ParameterKey=Environment,ParameterValue="$ENVIRONMENT" \
  --tags Key=Product,Value="GOV.UK One Login" \
         Key=System,Value="Orchestration" \
         Key=Environment,Value="$ENVIRONMENT" \
         Key=Owner,Value="di-orchestration@digital.cabinet-office.gov.uk"
```

### Updating the Stack

Set your AWS profile to the correct environment, run `export ENVIRONMENT=<environment>` then run:

```bash
aws cloudformation update-stack --stack-name txma \
  --template-body file://$(pwd)/template.yml \
  --region eu-west-2 \
  --parameters ParameterKey=Environment,ParameterValue="$ENVIRONMENT" \
  --tags Key=Product,Value="GOV.UK One Login" \
         Key=System,Value="Orchestration" \
         Key=Environment,Value="$ENVIRONMENT" \
         Key=Owner,Value="di-orchestration@digital.cabinet-office.gov.uk"
```