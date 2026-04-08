# Backup Vault Monitoring stack

This script deploys a cloudformation stack in Orch accounts which create a stack
to be able to monitor backups.

The template deployed is maintained by the Dev Platform Team and can be found
at this [link](https://github.com/govuk-one-login/backup-as-a-service/blob/82d0a6c67f9c92fad643c62d00a4cb96cf1e94d3/backup-vault-monitoring/template.yaml) .

AWS chat bot will need access to slack. There should be a slack workspace in the configured clients.
If not you will need to set one up manually. Instructions [here](https://govukverify.atlassian.net/wiki/spaces/PLAT/pages/3377168419/Slack+build+notifications+-+via+AWS+Chatbot) .

## Usage

The parameters for the template should be configured in a file at `<env>/parameters.json`. The tags to apply to created
resources should be configured in a file at `<env>/tags.json`.

The list of permitted environments is set up in the script. The script will automatically log in to the correct AWS
account and then create or update the Cloudformation stack using the parameters and tags provided. Only integration and
production have been setup as those are the environments that have backup enabled.

If you have not done so already, your AWS profiles will need to be configured.

### Create stack

```
./deploy.sh <env> --create
```

### Update stack

```
./deploy.sh <env>
```
