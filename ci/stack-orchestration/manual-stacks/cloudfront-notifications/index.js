import {
  GetSecretValueCommand,
  SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";

const secretsManagerClient = new SecretsManagerClient();

const getSecretWithId = async (secretArn) => {
  const getSecretCommand = new GetSecretValueCommand({
    SecretId: secretArn,
  });
  return (await secretsManagerClient.send(getSecretCommand)).SecretString;
};

const formatMessage = (snsMessage, colorCode, snsMessageFooter) => {
  var descriptionAndAccount = snsMessage.AlarmDescription.split("ACCOUNT:");
  var runbook = null;
  var account = snsMessage.AWSAccountId;
  if (descriptionAndAccount.length > 1) {
    const runbookSplit = descriptionAndAccount[1].split("Runbook: ");
    if (runbookSplit.length > 1) {
      runbook = runbookSplit[1];
    }
    account = runbookSplit[0];
  }
  var description = descriptionAndAccount[0];
  if (snsMessage.AlarmName.includes("pagerduty")) {
    if (snsMessage.NewStateValue === "ALARM") {
      description =
        description +
        "\n\nThis has triggered a PagerDuty alert for the following service:" +
        "\n<https://governmentdigitalservice.pagerduty.com/service-directory/P5V7FN6|GOV.UK One Login - Orchestration - P1>";
    }
    if (snsMessage.NewStateValue === "OK") {
      description =
        description +
        "\n\nThis has resolved the associated PagerDuty alert for the following service:" +
        "\n<https://governmentdigitalservice.pagerduty.com/service-directory/P5V7FN6|GOV.UK One Login - Orchestration - P1>";
    }
  }
  var fields = [
    {
      title: "Status",
      value: snsMessage.NewStateValue,
      short: false,
    },
    {
      title: "Account",
      value: account.trim(),
      short: false,
    },
  ];
  if (runbook != null) {
    fields.push({
      title: "Runbook",
      value: runbook.trim(),
      short: false,
    });
  }
  return {
    attachments: [
      {
        fallback: description.trim(),
        color: colorCode,
        title: snsMessage.AlarmName,
        text: description.trim(),
        fields: fields,
        footer: snsMessageFooter,
      },
    ],
  };
};

const sendAlertToSlack = async function (messageRequestBody) {
  const slackHookUrl = getSecretWithId(process.env.SLACK_WEBHOOK_SECRET_ARN);
  const messageRequest = {
    method: "post",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(messageRequestBody),
  };
  try {
    const response = await fetch(slackHookUrl, messageRequest);
    const message = await response.text();

    if (response.status !== 200) {
      console.error(
        "Slack webhook responded with non-200 status code: " + response.status,
      );
    }

    console.log(message);
  } catch (error) {
    console.log(error);
  }
};

export const handler = async function (event, _ignored) {
  console.log("Alert lambda triggered");
  let colorCode = "#C70039";
  let snsMessageFooter = "GOV.UK Sign In alert";

  let snsMessage = JSON.parse(event.Records[0].Sns.Message);
  if (snsMessage.NewStateValue === "OK") {
    colorCode = "#36a64f";
  }
  const messageRequestBody = formatMessage(
    snsMessage,
    colorCode,
    snsMessageFooter,
  );

  messageRequestBody.channel = await getSecretWithId(
    process.env.SLACK_CHANNEL_ID_SECRET_ARN,
  );

  console.log("Sending alert to slack");
  await sendAlertToSlack(messageRequestBody);
};
