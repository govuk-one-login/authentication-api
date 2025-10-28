import { SSMClient, GetParameterCommand } from "@aws-sdk/client-ssm";
const ssmClient = new SSMClient();

export const getParameter = async (parameterName) => {
  const getParameterCommand = new GetParameterCommand({
    Name: parameterName,
  });
  return (await ssmClient.send(getParameterCommand)).Parameter.Value;
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

export const sendAlertToSlack = async function (messageRequestBody) {
  const slackHookUrl =
    process.env.SLACK_WEBHOOK_URL ||
    (await getParameter(process.env.DEPLOY_ENVIRONMENT + "-slack-hook-url"));
  const messageRequest = {
    method: "post",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(messageRequestBody),
  };
  try {
    // eslint-disable-next-line no-undef
    const response = await fetch(slackHookUrl, messageRequest);
    const message = await response.text();
    console.log(message);
  } catch (error) {
    console.log(error);
  }
};

const getSlackChannel = async function () {
  if (process.env.SLACK_CHANNEL_ID) {
    return process.env.SLACK_CHANNEL_ID;
  } else if (process.env.SLACK_CHANNEL_PARAM) {
    return await getParameter(process.env.SLACK_CHANNEL_PARAM);
  } else {
    return await getParameter(
      process.env.DEPLOY_ENVIRONMENT + "-slack-channel-id",
    );
  }
};

// eslint-disable-next-line no-unused-vars
export const handler = async function (event, context) {
  console.log("Alert lambda triggered");
  let colorCode = process.env.ERROR_COLOR || "#C70039";
  let snsMessageFooter = process.env.MESSAGE_FOOTER || "GOV.UK Sign In alert";

  let snsMessage = JSON.parse(event.Records[0].Sns.Message);
  if (snsMessage.NewStateValue === "OK") {
    colorCode = process.env.OK_COLOR || "#36a64f";
  }
  const messageRequestBody = formatMessage(
    snsMessage,
    colorCode,
    snsMessageFooter,
  );

  messageRequestBody.channel = await getSlackChannel();

  console.log("Sending alert to slack");
  await sendAlertToSlack(messageRequestBody);
};
