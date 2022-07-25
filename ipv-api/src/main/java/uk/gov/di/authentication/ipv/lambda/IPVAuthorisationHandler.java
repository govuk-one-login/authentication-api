package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.entity.IPVAuthorisationRequest;
import uk.gov.di.authentication.ipv.entity.IPVAuthorisationResponse;
import uk.gov.di.authentication.ipv.services.IPVAuthorisationService;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.UNKNOWN;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class IPVAuthorisationHandler extends BaseFrontendHandler<IPVAuthorisationRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(IPVAuthorisationHandler.class);

    private final AuditService auditService;
    private final IPVAuthorisationService authorisationService;

    public IPVAuthorisationHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            AuditService auditService,
            IPVAuthorisationService authorisationService) {
        super(
                IPVAuthorisationRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.auditService = auditService;
        this.authorisationService = authorisationService;
    }

    public IPVAuthorisationHandler() {
        this(ConfigurationService.getInstance());
    }

    public IPVAuthorisationHandler(ConfigurationService configurationService) {
        super(IPVAuthorisationRequest.class, configurationService);
        this.auditService = new AuditService(configurationService);
        this.authorisationService =
                new IPVAuthorisationService(
                        configurationService,
                        new RedisConnectionService(configurationService),
                        new KmsConnectionService(configurationService));
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            IPVAuthorisationRequest request,
            UserContext userContext) {
        try {
            if (!configurationService.isIdentityEnabled()) {
                LOG.error("Identity is not enabled");
                throw new RuntimeException("Identity is not enabled");
            }
            var persistentId =
                    PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders());
            attachLogFieldToLogs(PERSISTENT_SESSION_ID, persistentId);
            var clientId = userContext.getClient().map(ClientRegistry::getClientID);
            attachLogFieldToLogs(CLIENT_ID, clientId.orElse(UNKNOWN));
            LOG.info("IPVAuthorisationHandler received request");
            var authRequest =
                    AuthenticationRequest.parse(
                            userContext.getClientSession().getAuthRequestParams());
            var pairwiseSubject =
                    ClientSubjectHelper.getSubjectWithSectorIdentifier(
                            userContext.getUserProfile().orElseThrow(),
                            configurationService.getIPVSector(),
                            authenticationService);
            var clientID = new ClientID(configurationService.getIPVAuthorisationClientId());
            var state = new State();
            var claimsSetRequest =
                    buildIpvClaimsRequest(authRequest)
                            .map(ClaimsSetRequest::toJSONString)
                            .orElse(null);
            var encryptedJWT =
                    authorisationService.constructRequestJWT(
                            state, authRequest.getScope(), pairwiseSubject, claimsSetRequest);
            var authRequestBuilder =
                    new AuthorizationRequest.Builder(
                                    new ResponseType(ResponseType.Value.CODE), clientID)
                            .endpointURI(configurationService.getIPVAuthorisationURI())
                            .requestObject(encryptedJWT);

            var ipvAuthorisationRequest = authRequestBuilder.build();
            authorisationService.storeState(userContext.getSession().getSessionId(), state);
            auditService.submitAuditEvent(
                    IPVAuditableEvent.IPV_AUTHORISATION_REQUESTED,
                    context.getAwsRequestId(),
                    userContext.getSession().getSessionId(),
                    clientId.orElse(AuditService.UNKNOWN),
                    AuditService.UNKNOWN,
                    request.getEmail(),
                    IpAddressHelper.extractIpAddress(input),
                    AuditService.UNKNOWN,
                    persistentId);

            LOG.info(
                    "IPVAuthorisationHandler successfully processed request, redirect URI {}",
                    ipvAuthorisationRequest.toURI().toString());

            return generateApiGatewayProxyResponse(
                    200, new IPVAuthorisationResponse(ipvAuthorisationRequest.toURI().toString()));

        } catch (ParseException | JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }

    private Optional<ClaimsSetRequest> buildIpvClaimsRequest(AuthenticationRequest authRequest) {
        return Optional.ofNullable(authRequest)
                .map(AuthenticationRequest::getOIDCClaims)
                .map(OIDCClaimsRequest::getUserInfoClaimsRequest);
    }
}
