package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.entity.Session;
import uk.gov.di.entity.VerifyCodeRequest;
import uk.gov.di.entity.VerifyCodeResponse;
import uk.gov.di.services.CodeStorageService;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.DynamoService;
import uk.gov.di.services.RedisConnectionService;
import uk.gov.di.services.SessionService;
import uk.gov.di.services.ValidationService;

import java.util.Optional;

import static uk.gov.di.entity.SessionState.EMAIL_CODE_NOT_VALID;
import static uk.gov.di.entity.SessionState.EMAIL_CODE_VERIFIED;
import static uk.gov.di.entity.SessionState.PHONE_NUMBER_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.entity.SessionState.PHONE_NUMBER_CODE_VERIFIED;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class VerifyCodeHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final SessionService sessionService;
    private final CodeStorageService codeStorageService;
    private final DynamoService dynamoService;
    private final ConfigurationService configurationService;
    private final ValidationService validationService;

    public VerifyCodeHandler(
            SessionService sessionService,
            CodeStorageService codeStorageService,
            DynamoService dynamoService,
            ConfigurationService configurationService,
            ValidationService validationService) {
        this.sessionService = sessionService;
        this.codeStorageService = codeStorageService;
        this.dynamoService = dynamoService;
        this.configurationService = configurationService;
        this.validationService = validationService;
    }

    public VerifyCodeHandler() {
        this.configurationService = new ConfigurationService();
        this.sessionService = new SessionService(configurationService);
        this.codeStorageService =
                new CodeStorageService(new RedisConnectionService(configurationService));
        this.dynamoService =
                new DynamoService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
        this.validationService = new ValidationService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        Optional<Session> session = sessionService.getSessionFromRequestHeaders(input.getHeaders());
        if (session.isEmpty()) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
        }

        try {
            VerifyCodeRequest codeRequest =
                    objectMapper.readValue(input.getBody(), VerifyCodeRequest.class);
            switch (codeRequest.getNotificationType()) {
                case VERIFY_EMAIL:
                    Optional<String> code =
                            codeStorageService.getCodeForEmail(session.get().getEmailAddress());

                    if (code.isEmpty() || !code.get().equals(codeRequest.getCode())) {
                        sessionService.save(session.get().setState(EMAIL_CODE_NOT_VALID));
                    } else {
                        codeStorageService.deleteCodeForEmail(session.get().getEmailAddress());
                        sessionService.save(session.get().setState(EMAIL_CODE_VERIFIED));
                    }
                    return generateApiGatewayProxyResponse(
                            200, new VerifyCodeResponse(session.get().getState()));
                case VERIFY_PHONE_NUMBER:
                    if (codeStorageService.isCodeBlockedForSession(
                            session.get().getEmailAddress(), session.get().getSessionId())) {
                        sessionService.save(
                                session.get().setState(PHONE_NUMBER_CODE_MAX_RETRIES_REACHED));
                    } else {
                        Optional<String> phoneNumberCode =
                                codeStorageService.getPhoneNumberCode(
                                        session.get().getEmailAddress());
                        sessionService.save(
                                session.get()
                                        .setState(
                                                validationService.validatePhoneVerificationCode(
                                                        phoneNumberCode,
                                                        codeRequest.getCode(),
                                                        session.get(),
                                                        configurationService
                                                                .getPhoneCodeMaxRetries())));
                        if (session.get().getState().equals(PHONE_NUMBER_CODE_VERIFIED)) {
                            codeStorageService.deletePhoneNumberCode(
                                    session.get().getEmailAddress());
                            dynamoService.updatePhoneNumberVerifiedStatus(
                                    session.get().getEmailAddress(), true);
                        } else if (session.get()
                                .getState()
                                .equals(PHONE_NUMBER_CODE_MAX_RETRIES_REACHED)) {
                            codeStorageService.saveCodeBlockedForSession(
                                    session.get().getEmailAddress(),
                                    session.get().getSessionId(),
                                    configurationService.getCodeExpiry());
                            sessionService.save(session.get().resetRetryCount());
                        }
                    }
                    return generateApiGatewayProxyResponse(
                            200, new VerifyCodeResponse(session.get().getState()));
            }
        } catch (JsonProcessingException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
        return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1002);
    }
}
