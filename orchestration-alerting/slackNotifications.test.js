import * as slackNotifications from "./slackNotifications";
describe("Slack alerts tests", () => {
  const SLACK_CHANNEL_ID = "test-slack-channel-id";
  const PAGERDUTY_CHANNEL_ID = "test-pagerduty-channel-id";
  const sendAlertToSlackMock = jest.fn();
  beforeEach(() => {
    process.env.DEPLOY_ENVIRONMENT = "dev";
    slackNotifications.sendAlertToSlack = sendAlertToSlackMock;
    slackNotifications.getParameter = jest.fn((param) => {
      if (param === "pagerduty-slack-channel-id") {
        return PAGERDUTY_CHANNEL_ID;
      }
      if (
        param === "dev-slack-channel-id" ||
        param === "production-slack-channel-id"
      ) {
        return SLACK_CHANNEL_ID;
      }
      return Promise.reject();
    });
  });
  afterEach(() => {
    jest.clearAllMocks();
  });

  it("Creates a slack message with alarm description and account", async () => {
    const message = createSnsMessage({
      AlarmDescription: "This is a test alarm. ACCOUNT: test-aws-account",
      AlarmName: "test-alarm",
      NewStateValue: "OK",
    });

    await slackNotifications.handler(message);

    expect(sendAlertToSlackMock).toHaveBeenCalledWith({
      attachments: [
        {
          fallback: "This is a test alarm.",
          color: "#36a64f",
          title: "test-alarm",
          text: "This is a test alarm.",
          fields: [
            {
              title: "Status",
              value: "OK",
              short: false,
            },
            {
              title: "Account",
              value: "test-aws-account",
              short: false,
            },
          ],
          footer: "GOV.UK Sign In alert",
        },
      ],
      channel: SLACK_CHANNEL_ID,
    });
  });

  it("Creates a slack message with alarm description, account, and runbook", async () => {
    const message = createSnsMessage({
      AlarmDescription:
        "This is a test alarm. ACCOUNT: test-aws-account. Runbook: http://example.com",
      AlarmName: "test-alarm",
      NewStateValue: "OK",
    });

    await slackNotifications.handler(message);

    expect(sendAlertToSlackMock).toHaveBeenCalledWith({
      attachments: [
        {
          fallback: "This is a test alarm.",
          color: "#36a64f",
          title: "test-alarm",
          text: "This is a test alarm.",
          fields: [
            {
              title: "Status",
              value: "OK",
              short: false,
            },
            {
              title: "Account",
              value: "test-aws-account.",
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
      channel: SLACK_CHANNEL_ID,
    });
  });

  it("Creates a slack message for pagerduty alarm in ALARM state", async () => {
    process.env.DEPLOY_ENVIRONMENT = "production";
    const message = createSnsMessage({
      AlarmDescription:
        "This is a test pagerduty alarm. ACCOUNT: test-aws-account. Runbook: http://example.com",
      AlarmName: "test-pagerduty-alarm",
      NewStateValue: "ALARM",
    });

    await slackNotifications.handler(message);

    const expectedChannels = [PAGERDUTY_CHANNEL_ID, SLACK_CHANNEL_ID];
    expectedChannels.forEach((expectedChannel) => {
      expect(sendAlertToSlackMock).toHaveBeenCalledWith({
        attachments: [
          {
            fallback:
              "This is a test pagerduty alarm. \n\n" +
              "This has triggered a PagerDuty alert for the following service:\n" +
              "<https://governmentdigitalservice.pagerduty.com/service-directory/P5V7FN6|GOV.UK One Login - Orchestration - P1>",
            color: "#C70039",
            title: "test-pagerduty-alarm",
            text:
              "This is a test pagerduty alarm. \n\n" +
              "This has triggered a PagerDuty alert for the following service:\n" +
              "<https://governmentdigitalservice.pagerduty.com/service-directory/P5V7FN6|GOV.UK One Login - Orchestration - P1>",
            fields: [
              {
                title: "Status",
                value: "ALARM",
                short: false,
              },
              {
                title: "Account",
                value: "test-aws-account.",
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
        channel: expectedChannel,
      });
    });
  });

  it("Creates a slack message for pagerduty alarm in OK state", async () => {
    process.env.DEPLOY_ENVIRONMENT = "production";
    const message = createSnsMessage({
      AlarmDescription:
        "This is a test pagerduty alarm. ACCOUNT: test-aws-account. Runbook: http://example.com",
      AlarmName: "test-pagerduty-alarm",
      NewStateValue: "OK",
    });

    await slackNotifications.handler(message);

    const expectedChannels = [PAGERDUTY_CHANNEL_ID, SLACK_CHANNEL_ID];
    expectedChannels.forEach((expectedChannel) => {
      expect(sendAlertToSlackMock).toHaveBeenCalledWith({
        attachments: [
          {
            fallback:
              "This is a test pagerduty alarm. \n\n" +
              "This has resolved the associated PagerDuty alert for the following service:\n" +
              "<https://governmentdigitalservice.pagerduty.com/service-directory/P5V7FN6|GOV.UK One Login - Orchestration - P1>",
            color: "#36a64f",
            title: "test-pagerduty-alarm",
            text:
              "This is a test pagerduty alarm. \n\n" +
              "This has resolved the associated PagerDuty alert for the following service:\n" +
              "<https://governmentdigitalservice.pagerduty.com/service-directory/P5V7FN6|GOV.UK One Login - Orchestration - P1>",
            fields: [
              {
                title: "Status",
                value: "OK",
                short: false,
              },
              {
                title: "Account",
                value: "test-aws-account.",
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
        channel: expectedChannel,
      });
    });
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
});
