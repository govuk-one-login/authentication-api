const { SSMClient, GetParameterCommand } = require("@aws-sdk/client-ssm");
const ssmClient = new SSMClient();

const getParameter = async (parameterName) => {
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
      value: account,
      short: false,
    },
  ];
  if (runbook != null) {
    fields.push({
      title: "Runbook",
      value: runbook,
      short: false,
    });
  }
  return {
    attachments: [
      {
        fallback: description,
        color: colorCode,
        title: snsMessage.AlarmName,
        text: description,
        fields: fields,
        footer: snsMessageFooter,
      },
    ],
  };
};

const buildMessageRequest = async function (
  snsMessage,
  colorCode,
  snsMessageFooter,
) {
  const body = formatMessage(snsMessage, colorCode, snsMessageFooter);
  const isNotBuildEnv = [
    "dev",
    "staging",
    "integration",
    "production",
  ].includes(process.env.DEPLOY_ENVIRONMENT);
  const isPagerDutyAlarm = snsMessage.AlarmName.includes("pagerduty");
  if (isPagerDutyAlarm && isEnabledForProd) {
    body.channel =
      process.env.SLACK_CHANNEL_ID ||
      (await getParameter("pagerduty-slack-channel-id"));
  } else if (isNotBuildEnv) {
    body.channel =
      process.env.SLACK_CHANNEL_ID ||
      (await getParameter(
        process.env.DEPLOY_ENVIRONMENT + "-slack-channel-id",
      ));
  }
  return {
    method: "post",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  };
};

const sendAlertToSlack = async function (slackHookUrl, messageRequest) {
  console.log("Sending alert to slack");
  try {
    // eslint-disable-next-line no-undef
    const response = await fetch(slackHookUrl, messageRequest);
    const message = await response.text();
    console.log(message);
  } catch (error) {
    console.log(error);
  }
};

// eslint-disable-next-line no-unused-vars
const handler = async function (event, context) {
  console.log("Alert lambda triggered");
  const slackHookUrl =
    process.env.SLACK_WEBHOOK_URL ||
    (await getParameter(process.env.DEPLOY_ENVIRONMENT + "-slack-hook-url"));
  let colorCode = process.env.ERROR_COLOR || "#C70039";
  let snsMessageFooter = process.env.MESSAGE_FOOTER || "GOV.UK Sign In alert";

  let snsMessage = JSON.parse(event.Records[0].Sns.Message);
  if (snsMessage.NewStateValue === "OK") {
    colorCode = process.env.OK_COLOR || "#36a64f";
  }
  const messageRequest = await buildMessageRequest(
    snsMessage,
    colorCode,
    snsMessageFooter,
  );

  await module.exports.sendAlertToSlack(slackHookUrl, messageRequest);
};

module.exports = { handler, sendAlertToSlack };
