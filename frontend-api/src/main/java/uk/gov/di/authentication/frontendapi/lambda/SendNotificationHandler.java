package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.exception.SdkClientException;
import uk.gov.di.authentication.frontendapi.entity.SendNotificationRequest;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.helpers.PhoneNumberHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Map;
import java.util.Optional;

import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1001;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1002;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1011;
import static uk.gov.di.authentication.shared.entity.NotificationType.ACCOUNT_CREATED_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.PersistentIdHelper.extractPersistentIdFromHeaders;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX;

public class SendNotificationHandler extends BaseFrontendHandler<SendNotificationRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(SendNotificationHandler.class);

    private final AwsSqsClient sqsClient;
    private final CodeGeneratorService codeGeneratorService;
    private final CodeStorageService codeStorageService;

    public SendNotificationHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            AwsSqsClient sqsClient,
            CodeGeneratorService codeGeneratorService,
            CodeStorageService codeStorageService) {
        super(
                SendNotificationRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.sqsClient = sqsClient;
        this.codeGeneratorService = codeGeneratorService;
        this.codeStorageService = codeStorageService;
    }

    public SendNotificationHandler() {
        super(SendNotificationRequest.class, ConfigurationService.getInstance());
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.codeGeneratorService = new CodeGeneratorService();
        this.codeStorageService = new CodeStorageService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            SendNotificationRequest request,
            UserContext userContext) {

        attachSessionIdToLogs(userContext.getSession());
        attachLogFieldToLogs(
                PERSISTENT_SESSION_ID, extractPersistentIdFromHeaders(input.getHeaders()));
        attachLogFieldToLogs(
                LogFieldName.CLIENT_ID,
                userContext.getClient().map(ClientRegistry::getClientID).orElse("unknown"));

        try {
            if (!userContext.getSession().validateSession(request.getEmail())) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
            }
            if (request.getNotificationType().equals(ACCOUNT_CREATED_CONFIRMATION)) {
                LOG.info("Placing message on queue for AccountCreatedConfirmation");
                NotifyRequest notifyRequest =
                        new NotifyRequest(request.getEmail(), ACCOUNT_CREATED_CONFIRMATION);
                if (notTestClientWithValidTestEmail(userContext, ACCOUNT_CREATED_CONFIRMATION)) {
                    sqsClient.send(objectMapper.writeValueAsString((notifyRequest)));
                    LOG.info("AccountCreatedConfirmation email placed on queue");
                }
                return generateEmptySuccessApiGatewayResponse();
            }
            Optional<ErrorResponse> codeRequestValid =
                    isCodeRequestAttemptValid(
                            request.getEmail(),
                            userContext.getSession(),
                            request.getNotificationType());
            if (codeRequestValid.isPresent()) {
                return generateApiGatewayProxyErrorResponse(400, codeRequestValid.get());
            }
            switch (request.getNotificationType()) {
                case VERIFY_EMAIL:
                    return handleNotificationRequest(
                            request.getEmail(),
                            request.getNotificationType(),
                            userContext.getSession(),
                            userContext);
                case VERIFY_PHONE_NUMBER:
                    if (request.getPhoneNumber() == null) {
                        return generateApiGatewayProxyResponse(400, ERROR_1011);
                    }
                    return handleNotificationRequest(
                            PhoneNumberHelper.removeWhitespaceFromPhoneNumber(
                                    request.getPhoneNumber()),
                            request.getNotificationType(),
                            userContext.getSession(),
                            userContext);
            }
            return generateApiGatewayProxyErrorResponse(400, ERROR_1002);
        } catch (SdkClientException ex) {
            LOG.error("Error sending message to queue");
            return generateApiGatewayProxyResponse(500, "Error sending message to queue");
        } catch (JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ERROR_1001);
        } catch (ClientNotFoundException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1015);
        }
    }

    private APIGatewayProxyResponseEvent handleNotificationRequest(
            String destination,
            NotificationType notificationType,
            Session session,
            UserContext userContext)
            throws JsonException, ClientNotFoundException {

        String code =
                codeStorageService
                        .getOtpCode(session.getEmailAddress(), notificationType)
                        .orElseGet(
                                () -> {
                                    String newCode = codeGeneratorService.sixDigitCode();
                                    codeStorageService.saveOtpCode(
                                            session.getEmailAddress(),
                                            newCode,
                                            configurationService.getCodeExpiry(),
                                            notificationType);
                                    return newCode;
                                });

        var notifyRequest = new NotifyRequest(destination, notificationType, code);

        sessionService.save(session.incrementCodeRequestCount());
        if (notTestClientWithValidTestEmail(userContext, notificationType)) {

            if (notificationType == VERIFY_PHONE_NUMBER) {
                CloudwatchMetricsService.putEmbeddedValue(
                        "SendingSms",
                        1,
                        Map.of(
                                "Environment",
                                configurationService.getEnvironment(),
                                "Country",
                                PhoneNumberHelper.getCountry(destination)));
            }

            sqsClient.send(objectMapper.writeValueAsString((notifyRequest)));
            LOG.info("Successfully processed request");
        }
        return generateEmptySuccessApiGatewayResponse();
    }

    private Optional<ErrorResponse> isCodeRequestAttemptValid(
            String email, Session session, NotificationType notificationType) {
        if (session.getCodeRequestCount() == configurationService.getCodeMaxRetries()) {
            LOG.info("User has requested too many OTP codes");
            codeStorageService.saveBlockedForEmail(
                    email,
                    CODE_REQUEST_BLOCKED_KEY_PREFIX,
                    configurationService.getBlockedEmailDuration());
            sessionService.save(session.resetCodeRequestCount());
            return Optional.of(getErrorResponseForCodeRequestLimitReached(notificationType));
        }
        if (codeStorageService.isBlockedForEmail(email, CODE_REQUEST_BLOCKED_KEY_PREFIX)) {
            LOG.info("User is blocked from requesting any OTP codes");
            return Optional.of(getErrorResponseForMaxCodeRequests(notificationType));
        }
        if (codeStorageService.isBlockedForEmail(email, CODE_BLOCKED_KEY_PREFIX)) {
            LOG.info("User is blocked from requesting any OTP codes");
            return Optional.of(getErrorResponseForMaxCodeAttempts(notificationType));
        }
        return Optional.empty();
    }

    private ErrorResponse getErrorResponseForCodeRequestLimitReached(
            NotificationType notificationType) {
        switch (notificationType) {
            case VERIFY_EMAIL:
                return ErrorResponse.ERROR_1029;
            case VERIFY_PHONE_NUMBER:
                return ErrorResponse.ERROR_1030;
            default:
                LOG.error("Invalid NotificationType sent");
                throw new RuntimeException("Invalid NotificationType sent");
        }
    }

    private ErrorResponse getErrorResponseForMaxCodeRequests(NotificationType notificationType) {
        switch (notificationType) {
            case VERIFY_EMAIL:
                return ErrorResponse.ERROR_1031;
            case VERIFY_PHONE_NUMBER:
                return ErrorResponse.ERROR_1032;
            default:
                LOG.error("Invalid NotificationType sent");
                throw new RuntimeException("Invalid NotificationType sent");
        }
    }

    private ErrorResponse getErrorResponseForMaxCodeAttempts(NotificationType notificationType) {
        switch (notificationType) {
            case VERIFY_EMAIL:
                return ErrorResponse.ERROR_1033;
            case VERIFY_PHONE_NUMBER:
                return ErrorResponse.ERROR_1034;
            default:
                LOG.error("Invalid NotificationType sent");
                throw new RuntimeException("Invalid NotificationType sent");
        }
    }

    private boolean notTestClientWithValidTestEmail(
            UserContext userContext, NotificationType notificationType)
            throws ClientNotFoundException {
        if (configurationService.isTestClientsEnabled()) {
            LOG.warn("TestClients are ENABLED");
        } else {
            return true;
        }
        String emailAddress = userContext.getSession().getEmailAddress();
        return userContext
                .getClient()
                .map(
                        clientRegistry -> {
                            if (clientRegistry.isTestClient()
                                    && clientRegistry
                                            .getTestClientEmailAllowlist()
                                            .contains(emailAddress)) {
                                LOG.info(
                                        "SendNotificationHandler not sending message on TestClientEmailAllowlist with NotificationType {}",
                                        notificationType);
                                return false;
                            } else {
                                return true;
                            }
                        })
                .orElseThrow(() -> new ClientNotFoundException(userContext.getSession()));
    }
}
