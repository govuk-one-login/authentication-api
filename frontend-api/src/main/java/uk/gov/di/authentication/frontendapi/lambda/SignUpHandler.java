package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.SignUpResponse;
import uk.gov.di.authentication.frontendapi.entity.SignupRequest;
import uk.gov.di.authentication.shared.conditions.ConsentHelper;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.ValidationHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.shared.validation.PasswordValidator;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Optional;

import static uk.gov.di.authentication.shared.entity.Session.AccountState.NEW;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.PersistentIdHelper.extractPersistentIdFromHeaders;

public class SignUpHandler extends BaseFrontendHandler<SignupRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(SignUpHandler.class);

    private final AuditService auditService;
    private final CommonPasswordsService commonPasswordsService;

    public SignUpHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            AuditService auditService,
            CommonPasswordsService commonPasswordsService) {
        super(
                SignupRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.auditService = auditService;
        this.commonPasswordsService = commonPasswordsService;
    }

    public SignUpHandler() {
        this(ConfigurationService.getInstance());
    }

    public SignUpHandler(ConfigurationService configurationService) {
        super(SignupRequest.class, configurationService);
        this.auditService = new AuditService(configurationService);
        this.commonPasswordsService = new CommonPasswordsService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            SignupRequest request,
            UserContext userContext) {

        attachSessionIdToLogs(userContext.getSession());
        attachLogFieldToLogs(
                PERSISTENT_SESSION_ID, extractPersistentIdFromHeaders(input.getHeaders()));
        attachLogFieldToLogs(
                CLIENT_ID,
                userContext.getClient().map(ClientRegistry::getClientID).orElse("unknown"));

        LOG.info("Received request");

        PasswordValidator passwordValidator = new PasswordValidator(commonPasswordsService);
        Optional<ErrorResponse> passwordValidationErrors = passwordValidator.validate(request.getPassword());

        if (passwordValidationErrors.isEmpty()) {
            if (authenticationService.userExists(request.getEmail())) {

                auditService.submitAuditEvent(
                        FrontendAuditableEvent.CREATE_ACCOUNT_EMAIL_ALREADY_EXISTS,
                        context.getAwsRequestId(),
                        userContext.getSession().getSessionId(),
                        userContext
                                .getClient()
                                .map(ClientRegistry::getClientID)
                                .orElse(AuditService.UNKNOWN),
                        AuditService.UNKNOWN,
                        request.getEmail(),
                        IpAddressHelper.extractIpAddress(input),
                        AuditService.UNKNOWN,
                        PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1009);
            }
            authenticationService.signUp(
                    request.getEmail(),
                    request.getPassword(),
                    new Subject(),
                    new TermsAndConditions(
                            configurationService.getTermsAndConditionsVersion(),
                            LocalDateTime.now(ZoneId.of("UTC")).toString()));
            var consentRequired = ConsentHelper.userHasNotGivenConsent(userContext);

            auditService.submitAuditEvent(
                    FrontendAuditableEvent.CREATE_ACCOUNT,
                    context.getAwsRequestId(),
                    userContext.getSession().getSessionId(),
                    userContext
                            .getClient()
                            .map(ClientRegistry::getClientID)
                            .orElse(AuditService.UNKNOWN),
                    AuditService.UNKNOWN,
                    request.getEmail(),
                    IpAddressHelper.extractIpAddress(input),
                    AuditService.UNKNOWN,
                    PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

            sessionService.save(
                    userContext
                            .getSession()
                            .setEmailAddress(request.getEmail())
                            .setNewAccount(NEW));

            LOG.info("Successfully processed request");
            try {
                return generateApiGatewayProxyResponse(200, new SignUpResponse(consentRequired));
            } catch (JsonException e) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
            }
        } else {
            return generateApiGatewayProxyErrorResponse(400, passwordValidationErrors.get());
        }
    }
}
