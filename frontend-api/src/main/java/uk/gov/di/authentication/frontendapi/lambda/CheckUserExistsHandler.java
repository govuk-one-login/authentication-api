package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.CheckUserExistsRequest;
import uk.gov.di.authentication.frontendapi.entity.CheckUserExistsResponse;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.ValidationHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class CheckUserExistsHandler extends BaseFrontendHandler<CheckUserExistsRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(CheckUserExistsHandler.class);

    private final AuditService auditService;
    private final CodeStorageService codeStorageService;

    public CheckUserExistsHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            AuditService auditService,
            CodeStorageService codeStorageService) {
        super(
                CheckUserExistsRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.auditService = auditService;
        this.codeStorageService = codeStorageService;
    }

    public CheckUserExistsHandler() {
        this(ConfigurationService.getInstance());
    }

    public CheckUserExistsHandler(ConfigurationService configurationService) {
        super(CheckUserExistsRequest.class, configurationService);
        this.auditService = new AuditService(configurationService);
        this.codeStorageService = new CodeStorageService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            CheckUserExistsRequest request,
            UserContext userContext) {

        attachSessionIdToLogs(userContext.getSession());

        try {
            LOG.info("Processing request");

            String emailAddress = request.getEmail().toLowerCase();
            Optional<ErrorResponse> errorResponse =
                    ValidationHelper.validateEmailAddress(emailAddress);
            String persistentSessionId =
                    PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders());
            if (errorResponse.isPresent()) {
                auditService.submitAuditEvent(
                        FrontendAuditableEvent.CHECK_USER_INVALID_EMAIL,
                        userContext.getClientSessionId(),
                        userContext.getSession().getSessionId(),
                        userContext
                                .getClient()
                                .map(ClientRegistry::getClientID)
                                .orElse(AuditService.UNKNOWN),
                        AuditService.UNKNOWN,
                        emailAddress,
                        IpAddressHelper.extractIpAddress(input),
                        AuditService.UNKNOWN,
                        persistentSessionId);
                return generateApiGatewayProxyErrorResponse(400, errorResponse.get());
            }

            var incorrectPasswordCount = codeStorageService.getIncorrectPasswordCount(emailAddress);

            if (incorrectPasswordCount >= configurationService.getMaxPasswordRetries()) {
                LOG.info("User account is locked");

                auditService.submitAuditEvent(
                        FrontendAuditableEvent.ACCOUNT_TEMPORARILY_LOCKED,
                        userContext.getClientSessionId(),
                        userContext.getSession().getSessionId(),
                        userContext.getClientId(),
                        AuditService.UNKNOWN,
                        emailAddress,
                        IpAddressHelper.extractIpAddress(input),
                        AuditService.UNKNOWN,
                        persistentSessionId);

                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1045);
            }

            var userProfile = authenticationService.getUserProfileByEmailMaybe(emailAddress);
            var userExists = userProfile.isPresent();
            userContext.getSession().setEmailAddress(emailAddress);
            AuditableEvent auditableEvent;
            var rpPairwiseId = AuditService.UNKNOWN;
            var internalPairwiseId = AuditService.UNKNOWN;
            if (userExists) {
                auditableEvent = FrontendAuditableEvent.CHECK_USER_KNOWN_EMAIL;
                rpPairwiseId =
                        ClientSubjectHelper.getSubject(
                                        userProfile.get(),
                                        userContext.getClient().get(),
                                        authenticationService,
                                        configurationService.getInternalSectorUri())
                                .getValue();
                internalPairwiseId =
                        ClientSubjectHelper.getSubjectWithSectorIdentifier(
                                        userProfile.get(),
                                        configurationService.getInternalSectorUri(),
                                        authenticationService)
                                .getValue();
            } else {
                auditableEvent = FrontendAuditableEvent.CHECK_USER_NO_ACCOUNT_WITH_EMAIL;
            }
            auditService.submitAuditEvent(
                    auditableEvent,
                    userContext.getClientSessionId(),
                    userContext.getSession().getSessionId(),
                    userContext
                            .getClient()
                            .map(ClientRegistry::getClientID)
                            .orElse(AuditService.UNKNOWN),
                    internalPairwiseId,
                    emailAddress,
                    IpAddressHelper.extractIpAddress(input),
                    AuditService.UNKNOWN,
                    persistentSessionId,
                    pair("rpPairwiseId", rpPairwiseId));
            CheckUserExistsResponse checkUserExistsResponse =
                    new CheckUserExistsResponse(emailAddress, userExists);
            sessionService.save(userContext.getSession());

            LOG.info("Successfully processed request");

            return generateApiGatewayProxyResponse(200, checkUserExistsResponse);

        } catch (JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }
}
