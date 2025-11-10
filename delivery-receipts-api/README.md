# delivery-receipts-api

The Delivery Receipts API is a [callback handler](https://docs.notifications.service.gov.uk/java.html#callbacks) for consumption by Notify.

When called by Notify the handler adds a Cloudwatch metric to track how many messages were sent by Notify, whether they were emails or SMS, and which template was used.
The output can be seen in the [Grafana - Authentication - Notify Metrics](https://g-8e26091ad7.grafana-workspace.eu-west-2.amazonaws.com/d/ufjJdaR4z/authentication-notify-metrics?orgId=1) Dashboard.

At the moment the handler is deployed to both Integration and Production, but is only actually connected to Notify in Production.

## Testing the handler

The handler is not currently deployed to Build or Staging, but can be tested in Integration.

1. Go to API Gateway in the AWS Console
1. Find the `env-di-authentication-delivery-receipts-api`
1. Click on `POST` under `/notify-callback`
1. Select the 'TEST' tab
1. Go to 'Systems Manager -> Parameter Store'
1. Find the `env-notify-callback-bearer-token` and take a copy of the token
1. Back in the 'TEST' tab in API Gateway, paste in the bearer token as a header in the format `Authorization:Bearer token-value`
1. Paste the following test json payload data into the body field:
   ```
   {
     "id": "0qdAiQw2eeF4Xh51etaIwUXc_Ww",
     "reference": null,
     "to": "n.e.user@digital.cabinet-office.gov.uk",
     "status": "delivered",
     "created_at": "Wed Sep 20 11:37:41 BST 2023",
     "completed_at": "Wed Sep 20 11:37:41 BST 2023",
     "sent_at": "Wed Sep 20 11:37:41 BST 2023",
     "notification_type": "email",
     "template_id": "35454-543543-3435435-12340",
     "template_version": 1
   }
   ```
1. Click the 'Test' button to test the callback lambda, which will then display the output.
