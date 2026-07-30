import { Context, SNSEvent } from "aws-lambda";
import {
  handler,
  sendAlertToSlack,
  AlarmData,
  SlackMessage,
} from "./slackNotifications";
import { GetParameterCommand } from "@aws-sdk/client-ssm";

const SLACK_CHANNEL_ID = "test-slack-channel-id";
const PAGERDUTY_CHANNEL_ID = "test-pagerduty-channel-id";
const PAGERDUTY_CHANNEL_PARAM = "pagerduty-slack-channel-id";
const SLACK_WEBOOK_URL = "test-webhook-url";

vi.mock("@aws-sdk/client-ssm", () => ({
  SSMClient: class {
    send = (command: GetParameterCommand) => {
      let value = "";
      const param = command.input.Name;
      if (param === PAGERDUTY_CHANNEL_PARAM) {
        value = PAGERDUTY_CHANNEL_ID;
      }
      if (
        param === "dev-slack-channel-id" ||
        param === "production-slack-channel-id"
      ) {
        value = SLACK_CHANNEL_ID;
      }
      if (
        param === "dev-slack-hook-url" ||
        param === "production-slack-hook-url"
      ) {
        value = SLACK_WEBOOK_URL;
      }
      return { Parameter: { Value: value } };
    };
  },
  GetParameterCommand: class {
    input: { Name: string };
    constructor(input: { Name: string }) {
      this.input = input;
    }
  },
}));

const mockFetch = vi
  .fn()
  .mockResolvedValue({ text: () => Promise.resolve("ok") });
vi.stubGlobal("fetch", mockFetch);

describe("Slack alerts tests", () => {
  beforeEach(() => {
    process.env.DEPLOY_ENVIRONMENT = "dev";
    process.env.SLACK_CHANNEL_PARAM = "";
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("Creates a slack message with alarm description and account", async () => {
    const message = createSnsMessage({
      AlarmDescription: "This is a test alarm. ACCOUNT: test-aws-account",
      AlarmName: "test-alarm",
      NewStateValue: "OK",
      AWSAccountId: "test-acc-id",
    });

    await handler(message, {} as Context);

    expectSlackMessageSent({
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
      AWSAccountId: "test-acc-id",
    });

    await handler(message, {} as Context);

    expectSlackMessageSent({
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
      AWSAccountId: "test-acc-id",
    });

    await handler(message, {} as Context);

    expectSlackMessageSent({
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
      channel: SLACK_CHANNEL_ID,
    });
  });

  it("Creates a slack message for pagerduty alarm in OK state", async () => {
    process.env.DEPLOY_ENVIRONMENT = "production";
    const message = createSnsMessage({
      AlarmDescription:
        "This is a test pagerduty alarm. ACCOUNT: test-aws-account. Runbook: http://example.com",
      AlarmName: "test-pagerduty-alarm",
      NewStateValue: "OK",
      AWSAccountId: "test-acc-id",
    });

    await handler(message, {} as Context);

    expectSlackMessageSent({
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
      channel: SLACK_CHANNEL_ID,
    });
  });
  it("Creates a slack message with channel parameter passed as env var", async () => {
    process.env.SLACK_CHANNEL_PARAM = "pagerduty-slack-channel-id";
    const message = createSnsMessage({
      AlarmDescription: "This is a test alarm. ACCOUNT: test-aws-account",
      AlarmName: "test-alarm",
      NewStateValue: "OK",
      AWSAccountId: "test-acc-id",
    });

    await handler(message, {} as Context);

    expectSlackMessageSent({
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
      channel: PAGERDUTY_CHANNEL_ID,
    });
  });

  const createSnsMessage = function (alarm: AlarmData): SNSEvent {
    return {
      Records: [
        {
          Sns: {
            Message: JSON.stringify(alarm),
            SignatureVersion: "",
            Timestamp: "",
            Signature: "",
            SigningCertUrl: "",
            MessageId: "",
            MessageAttributes: {},
            Type: "",
            UnsubscribeUrl: "",
            TopicArn: "",
          },
          EventVersion: "",
          EventSubscriptionArn: "",
          EventSource: "",
        },
      ],
    };
  };

  const expectSlackMessageSent = (message: SlackMessage) => {
    expect(mockFetch).toHaveBeenCalledWith(SLACK_WEBOOK_URL, {
      method: "post",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(message),
    });
  };
});
