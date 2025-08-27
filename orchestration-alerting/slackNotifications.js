const { SSMClient, GetParameterCommand } = require("@aws-sdk/client-ssm");
const ssmClient = new SSMClient();

const getParameter = async (parameterName) => {
  const getParameterCommand = new GetParameterCommand({
    Name: parameterName,
  });
  return (await ssmClient.send(getParameterCommand)).Parameter.Value;
};

const formatMessage = (snsMessage, colorCode, snsMessageFooter) => {
  var description = snsMessage.AlarmDescription.split("ACCOUNT:");
  var account = snsMessage.AWSAccountId;
  if (description.length > 1) {
    account = description[1];
  }
  return {
    attachments: [
      {
        fallback: description[0],
        color: colorCode,
        title: snsMessage.AlarmName,
        text: description[0],
        fields: [
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
        ],
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
  const isEnabledForNonProd = ["dev", "staging", "integration"].includes(
    process.env.DEPLOY_ENVIRONMENT,
  );
  const isEnabledForProd =
    process.env.PROD_ALERTS_ENABLED === "true" &&
    process.env.DEPLOY_ENVIRONMENT === "production";
  if (isEnabledForNonProd || isEnabledForProd) {
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

module.exports = { handler };
