package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.SignupRequest;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.shared.validation.PasswordValidator;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Optional;

import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_CREATE_ACCOUNT_EMAIL_ALREADY_EXISTS;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class SignUpHandler extends BaseFrontendHandler<SignupRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(SignUpHandler.class);

    private final AuditService auditService;
    private final CommonPasswordsService commonPasswordsService;
    private final PasswordValidator passwordValidator;

    public SignUpHandler(
            ConfigurationService configurationService,
            ClientService clientService,
            AuthenticationService authenticationService,
            AuditService auditService,
            CommonPasswordsService commonPasswordsService,
            PasswordValidator passwordValidator,
            AuthSessionService authSessionService) {
        super(
                SignupRequest.class,
                configurationService,
                clientService,
                authenticationService,
                authSessionService);
        this.auditService = auditService;
        this.commonPasswordsService = commonPasswordsService;
        this.passwordValidator = passwordValidator;
    }

    public SignUpHandler() {
        this(ConfigurationService.getInstance());
    }

    public SignUpHandler(ConfigurationService configurationService) {
        super(SignupRequest.class, configurationService);
        this.auditService = new AuditService(configurationService);
        this.commonPasswordsService = new CommonPasswordsService(configurationService);
        this.passwordValidator = new PasswordValidator(commonPasswordsService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return super.handleRequest(input, context);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            SignupRequest request,
            UserContext userContext) {

        attachSessionIdToLogs(userContext.getAuthSession().getSessionId());

        AuthSessionItem authSessionItem = userContext.getAuthSession();

        LOG.info("Received request");

        Optional<ErrorResponse> passwordValidationError =
                passwordValidator.validate(request.getPassword());

        var auditContext =
                auditContextFromUserContext(
                        userContext,
                        AuditService.UNKNOWN,
                        request.getEmail(),
                        IpAddressHelper.extractIpAddress(input),
                        AuditService.UNKNOWN,
                        PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

        if (passwordValidationError.isEmpty()) {
            LOG.info("No password validation errors found");
            if (authenticationService.userExists(request.getEmail())) {

                auditService.submitAuditEvent(
                        AUTH_CREATE_ACCOUNT_EMAIL_ALREADY_EXISTS, auditContext);

                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1009);
            }
            var user =
                    authenticationService.signUp(
                            request.getEmail(),
                            request.getPassword(),
                            new Subject(),
                            new TermsAndConditions(
                                    configurationService.getTermsAndConditionsVersion(),
                                    LocalDateTime.now(ZoneId.of("UTC")).toString()));

            LOG.info("Calculating internal common subject identifier");
            var internalCommonSubjectId =
                    ClientSubjectHelper.getSubjectWithSectorIdentifier(
                            user.getUserProfile(),
                            configurationService.getInternalSectorUri(),
                            authenticationService);
            auditContext = auditContext.withSubjectId(internalCommonSubjectId.getValue());

            LOG.info("Calculating RP pairwise identifier");
            var rpPairwiseId =
                    userContext
                            .getClient()
                            .map(
                                    client ->
                                            ClientSubjectHelper.getSubject(
                                                            user.getUserProfile(),
                                                            client,
                                                            authSessionItem,
                                                            authenticationService,
                                                            configurationService
                                                                    .getInternalSectorUri())
                                                    .getValue())
                            .orElse(AuditService.UNKNOWN);

            auditService.submitAuditEvent(
                    FrontendAuditableEvent.AUTH_CREATE_ACCOUNT,
                    auditContext,
                    pair("internalSubjectId", user.getUserProfile().getSubjectID()),
                    pair("rpPairwiseId", rpPairwiseId));

            LOG.info("Setting internal common subject identifier in user session");

            authSessionService.updateSession(
                    authSessionItem
                            .withAccountState(AuthSessionItem.AccountState.NEW)
                            .withEmailAddress(request.getEmail())
                            .withInternalCommonSubjectId(internalCommonSubjectId.getValue()));
            LOG.info("Successfully processed request");
            return generateApiGatewayProxyResponse(200, "");
        } else {
            LOG.info("Error message: {}", passwordValidationError.get().getMessage());
            return generateApiGatewayProxyErrorResponse(400, passwordValidationError.get());
        }
    }
}
