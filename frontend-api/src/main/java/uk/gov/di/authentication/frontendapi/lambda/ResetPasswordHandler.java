package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.ConstraintViolationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.ResetPasswordWithCodeRequest;
import uk.gov.di.authentication.frontendapi.services.AwsSqsClient;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.helpers.Argon2MatcherHelper;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.ValidationService;

import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class ResetPasswordHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final AuthenticationService authenticationService;
    private final AwsSqsClient sqsClient;
    private final CodeStorageService codeStorageService;
    private final ValidationService validationService;
    private final ObjectMapper objectMapper = ObjectMapperFactory.getInstance();

    private static final Logger LOGGER = LogManager.getLogger(ResetPasswordHandler.class);

    public ResetPasswordHandler(
            AuthenticationService authenticationService,
            AwsSqsClient sqsClient,
            CodeStorageService codeStorageService,
            ValidationService validationService) {
        this.authenticationService = authenticationService;
        this.sqsClient = sqsClient;
        this.codeStorageService = codeStorageService;
        this.validationService = validationService;
    }

    public ResetPasswordHandler() {
        this(ConfigurationService.getInstance());
    }

    public ResetPasswordHandler(ConfigurationService configurationService) {
        this.authenticationService = new DynamoService(configurationService);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.codeStorageService =
                new CodeStorageService(new RedisConnectionService(configurationService));
        this.validationService = new ValidationService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            LOGGER.info("Request received to ResetPasswordHandler");
                            try {
                                ResetPasswordWithCodeRequest resetPasswordWithCodeRequest =
                                        objectMapper.readValue(
                                                input.getBody(),
                                                ResetPasswordWithCodeRequest.class);
                                Optional<ErrorResponse> errorResponse =
                                        validationService.validatePassword(
                                                resetPasswordWithCodeRequest.getPassword());
                                if (errorResponse.isPresent()) {
                                    LOGGER.info(
                                            "Password did not pass validation because: {}",
                                            errorResponse.get().getMessage());
                                    return generateApiGatewayProxyErrorResponse(
                                            400, errorResponse.get());
                                }
                                Optional<String> subject =
                                        codeStorageService.getSubjectWithPasswordResetCode(
                                                resetPasswordWithCodeRequest.getCode());
                                if (subject.isEmpty()) {
                                    LOGGER.error("Subject is not found in Redis");
                                    return generateApiGatewayProxyErrorResponse(
                                            400, ErrorResponse.ERROR_1021);
                                }
                                UserCredentials userCredentials =
                                        authenticationService.getUserCredentialsFromSubject(
                                                subject.get());
                                if (verifyPassword(
                                        userCredentials.getPassword(),
                                        resetPasswordWithCodeRequest.getPassword())) {
                                    LOGGER.info("New password is the same as the old password");
                                    return generateApiGatewayProxyErrorResponse(
                                            400, ErrorResponse.ERROR_1024);
                                }
                                codeStorageService.deleteSubjectWithPasswordResetCode(
                                        resetPasswordWithCodeRequest.getCode());
                                authenticationService.updatePassword(
                                        userCredentials.getEmail(),
                                        resetPasswordWithCodeRequest.getPassword());

                                int incorrectPasswordCount =
                                        codeStorageService.getIncorrectPasswordCount(
                                                userCredentials.getEmail());
                                if (incorrectPasswordCount != 0) {
                                    codeStorageService.deleteIncorrectPasswordCount(
                                            userCredentials.getEmail());
                                }

                                NotifyRequest notifyRequest =
                                        new NotifyRequest(
                                                userCredentials.getEmail(),
                                                NotificationType.PASSWORD_RESET_CONFIRMATION);
                                LOGGER.info("Placing message on queue");
                                sqsClient.send(serialiseRequest(notifyRequest));
                            } catch (JsonProcessingException | ConstraintViolationException e) {
                                LOGGER.error("Incorrect parameters in ResetPassword request");
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1001);
                            }
                            LOGGER.info("Generating successful response");
                            return generateEmptySuccessApiGatewayResponse();
                        });
    }

    private String serialiseRequest(Object request) throws JsonProcessingException {
        return objectMapper.writeValueAsString(request);
    }

    private static boolean verifyPassword(String hashedPassword, String password) {
        return Argon2MatcherHelper.matchRawStringWithEncoded(password, hashedPassword);
    }
}
