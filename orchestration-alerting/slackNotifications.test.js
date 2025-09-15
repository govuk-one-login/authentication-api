const slackNotifications = require("./slackNotifications");
describe("Slack alerts tests", () => {
  const SLACK_CHANNEL_ID = "test-slack-channel-id";
  const SLACK_WEBHOOK_URL = "http://localhost/api";
  const sendAlertToSlackSpy = jest
    .spyOn(slackNotifications, "sendAlertToSlack")
    .mockResolvedValue(1);
  beforeEach(() => {
    process.env.SLACK_CHANNEL_ID = SLACK_CHANNEL_ID;
    process.env.SLACK_WEBHOOK_URL = SLACK_WEBHOOK_URL;
  });

  it("Creates a slack message with alarm description and account", async () => {
    const message = createSnsMessage({
      AlarmDescription: "This is a test alarm. ACCOUNT: test-aws-account",
      AlarmName: "test-alarm",
      NewStateValue: "OK",
    });
    await slackNotifications.handler(message, null);
    expect(sendAlertToSlackSpy).toHaveBeenCalledWith(
      SLACK_WEBHOOK_URL,
      createSlackPostRequest({
        attachments: [
          {
            fallback: "This is a test alarm. ",
            color: "#36a64f",
            title: "test-alarm",
            text: "This is a test alarm. ",
            fields: [
              {
                title: "Status",
                value: "OK",
                short: false,
              },
              {
                title: "Account",
                value: " test-aws-account",
                short: false,
              },
            ],
            footer: "GOV.UK Sign In alert",
          },
        ],
      }),
    );
  });
  it("Creates a slack message with alarm description, account, and runbook", async () => {
    const message = createSnsMessage({
      AlarmDescription:
        "This is a test alarm. ACCOUNT: test-aws-account. Runbook: http://example.com",
      AlarmName: "test-alarm",
      NewStateValue: "OK",
    });
    await slackNotifications.handler(message, null);
    expect(sendAlertToSlackSpy).toHaveBeenCalledWith(
      SLACK_WEBHOOK_URL,
      createSlackPostRequest({
        attachments: [
          {
            fallback: "This is a test alarm. ",
            color: "#36a64f",
            title: "test-alarm",
            text: "This is a test alarm. ",
            fields: [
              {
                title: "Status",
                value: "OK",
                short: false,
              },
              {
                title: "Account",
                value: " test-aws-account. ",
                short: false,
              },
              {
                title: "Runbook",
                value: "http://example.com",
                short: false,
              },
            ],
            footer: "GOV.UK Sign In alert",
          },
        ],
      }),
    );
  });
  const createSnsMessage = function (alarm) {
    return {
      Records: [
        {
          Sns: {
            Message: JSON.stringify(alarm),
          },
        },
      ],
    };
  };
  const createSlackPostRequest = function (slackMessageRequest) {
    return {
      body: JSON.stringify(slackMessageRequest),
      headers: { "Content-Type": "application/json" },
      method: "post",
    };
  };
});
