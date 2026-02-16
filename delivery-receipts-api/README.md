# delivery-receipts-api

The Delivery Receipts API is a [callback handler](https://docs.notifications.service.gov.uk/java.html#callbacks) for
consumption by Notify.

When called by Notify the handler adds a Cloudwatch metric to track how many messages were sent by Notify, whether they
were emails or SMS, and which template was used.
The output can be seen in
the [Grafana - Authentication - Notify Metrics](https://g-8e26091ad7.grafana-workspace.eu-west-2.amazonaws.com/d/ufjJdaR4z/authentication-notify-metrics?orgId=1)
Dashboard.

The handler is deployed to both Integration and Production, but is only actually connected to Notify in Production.

Post secure pipeline migration the handler is deployed to and can be tested in all environments. It is not connected to
Notify, this can be done ad-hoc if required.
Only one endpoint at a time can be connected to Notify as each account supports a single callback endpoint.

## Testing the handler

In the strategic accounts the handler is deployed in all environments. Sandpit has now been removed.

### Testing in the AWS Console

1. Go to API Gateway in the AWS Console
1. Find the `env-di-authentication-delivery-receipts-api`
1. Click on `POST` under `/notify-callback`
1. Select the 'TEST' tab
1. Go to 'Systems Manager -> Parameter Store'
1. Find the `env-notify-callback-bearer-token` and take a copy of the token (requires admin or poweruser)
1. Back in the 'TEST' tab in API Gateway, paste in the bearer token as a header in the format
   `Authorization:Bearer token-value`
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

### Testing with curl

1. Go to API Gateway in the AWS Console
1. Find the `env-di-authentication-delivery-receipts-api`
1. Take a copy of the url for the `/notify-callback` `POST` method under `stages/env`
1. Go to 'Systems Manager -> Parameter Store'
1. Find the `env-notify-callback-bearer-token` and take a copy of the token (requires admin or poweruser)
1. Substitute the url and bearer token then run the following command:

```
curl -X POST https://<api-id>.execute-api.eu-west-2.amazonaws.com/<env>/notify-callback \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer your-bearer-token" \
    -d '{
        "id": "740e5834-3a29-46b4-9a6f-16142fde533a",
        "reference": "12345678",
        "to": "07700912345",
        "status": "delivered",
        "created_at": "2017-05-14T12:15:30.000000Z",
        "completed_at": "2017-05-14T12:15:30.000000Z",
        "sent_at": "2017-05-14T12:15:30.000000Z",
        "notification_type": "sms",
        "template_id": "97b956c8-9a12-451a-994b-5d51741b63d4",
        "template_version": 1
    }'
```

The `template_id` should be a real template id in the Notify account otherwise the api generates an error (the one in
the body above is a real id in the test account).
For `"notification_type": "email"` use `"template_id": "a15995f7-94a3-4a1b-9da0-54b1a8b5cc12"`
