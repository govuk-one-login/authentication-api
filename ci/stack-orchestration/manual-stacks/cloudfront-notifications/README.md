## Cloudfront Notification Stack

This stack contains an SNS topic with either a PagerDuty integration in production or Lambda -> Slack integration in non
production environments.

This stack requires some manual secrets to be setup as part of the initial setup process. These are contained within the
template and should be setup as part of deploying this stack.

On initial deployment, the parameters to deploy the PagerDuty/Slack integration should be set to "No". This will deploy
the relevant secrets to support the integration. Once you've deployed this and set up the required secrets, you can enable
the Slack/PagerDuty integration parameters.
