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
import uk.gov.di.authentication.ipv.entity.IPVCallbackNoSessionException;
import uk.gov.di.authentication.ipv.services.IPVAuthorisationService;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ErrorResponse;
import uk.gov.di.orchestration.shared.entity.UserProfile;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.ClientNotFoundException;
import uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper;
import uk.gov.di.orchestration.shared.helpers.IpAddressHelper;
import uk.gov.di.orchestration.shared.helpers.PersistentIdHelper;
import uk.gov.di.orchestration.shared.lambda.BaseFrontendHandler;
import uk.gov.di.orchestration.shared.serialization.Json.JsonException;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.AuthenticationService;
import uk.gov.di.orchestration.shared.services.ClientService;
import uk.gov.di.orchestration.shared.services.ClientSessionService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;
import uk.gov.di.orchestration.shared.services.NoSessionOrchestrationService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;
import uk.gov.di.orchestration.shared.services.SessionService;
import uk.gov.di.orchestration.shared.state.UserContext;

import java.util.Map;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.UNKNOWN;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;
import static uk.gov.di.orchestration.shared.services.AuditService.MetadataPair.pair;

public class IPVAuthorisationHandler extends BaseFrontendHandler<IPVAuthorisationRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(IPVAuthorisationHandler.class);

    private final AuditService auditService;
    private final IPVAuthorisationService authorisationService;
    private final NoSessionOrchestrationService noSessionOrchestrationService;
    private final CloudwatchMetricsService cloudwatchMetricsService;

    public IPVAuthorisationHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            AuditService auditService,
            IPVAuthorisationService authorisationService,
            NoSessionOrchestrationService noSessionOrchestrationService,
            CloudwatchMetricsService cloudwatchMetricsService) {
        super(
                IPVAuthorisationRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.auditService = auditService;
        this.authorisationService = authorisationService;
        this.noSessionOrchestrationService = noSessionOrchestrationService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
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
        this.noSessionOrchestrationService =
                new NoSessionOrchestrationService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
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
            IPVAuthorisationRequest request,
            UserContext userContext) {
        try {
            if (!configurationService.isIdentityEnabled()) {
                LOG.error("Identity is not enabled");
                throw new RuntimeException("Identity is not enabled");
            }
            var persistentId =
                    PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders());
            var rpClientID = userContext.getClient().map(ClientRegistry::getClientID);
            attachLogFieldToLogs(CLIENT_ID, rpClientID.orElse(UNKNOWN));
            LOG.info("IPVAuthorisationHandler received request");
            var authRequest =
                    AuthenticationRequest.parse(
                            userContext.getClientSession().getAuthRequestParams());
            var pairwiseSubject =
                    ClientSubjectHelper.getSubjectWithSectorIdentifier(
                            userContext.getUserProfile().orElseThrow(),
                            configurationService.getInternalSectorURI(),
                            authenticationService);
            var state = new State();
            var claimsSetRequest = buildIpvClaimsRequest(authRequest).orElse(null);

            var clientSessionId =
                    getHeaderValueFromHeaders(
                            input.getHeaders(),
                            CLIENT_SESSION_ID_HEADER,
                            configurationService.getHeadersCaseInsensitive());
            var clientSession =
                    clientSessionService
                            .getClientSession(clientSessionId)
                            .orElseThrow(
                                    () ->
                                            new IPVCallbackNoSessionException(
                                                    "ClientSession not found"));
            var vtrList = clientSession.getVtrList();

            var encryptedJWT =
                    authorisationService.constructRequestJWT(
                            state,
                            authRequest.getScope(),
                            pairwiseSubject,
                            claimsSetRequest,
                            Optional.ofNullable(clientSessionId).orElse("unknown"),
                            userContext.getUserProfile().map(UserProfile::getEmail).orElseThrow(),
                            VectorOfTrust.getRequestedLevelsOfConfidence(vtrList),
                            false);
            var authRequestBuilder =
                    new AuthorizationRequest.Builder(
                                    new ResponseType(ResponseType.Value.CODE),
                                    new ClientID(
                                            configurationService.getIPVAuthorisationClientId()))
                            .endpointURI(configurationService.getIPVAuthorisationURI())
                            .requestObject(encryptedJWT);

            var ipvAuthorisationRequest = authRequestBuilder.build();
            authorisationService.storeState(userContext.getSession().getSessionId(), state);
            noSessionOrchestrationService.storeClientSessionIdAgainstState(clientSessionId, state);

            LOG.info("Calculating RP pairwise identifier");
            var rpPairwiseId =
                    ClientSubjectHelper.getSubject(
                                    userContext.getUserProfile().orElseThrow(),
                                    userContext
                                            .getClient()
                                            .orElseThrow(
                                                    () ->
                                                            new ClientNotFoundException(
                                                                    userContext.getSession())),
                                    authenticationService,
                                    configurationService.getInternalSectorURI())
                            .getValue();

            var user =
                    TxmaAuditUser.user()
                            .withGovukSigninJourneyId(clientSessionId)
                            .withSessionId(userContext.getSession().getSessionId())
                            .withUserId(
                                    userContext.getSession().getInternalCommonSubjectIdentifier())
                            .withEmail(request.getEmail())
                            .withIpAddress(IpAddressHelper.extractIpAddress(input))
                            .withPersistentSessionId(persistentId);

            auditService.submitAuditEvent(
                    IPVAuditableEvent.IPV_AUTHORISATION_REQUESTED,
                    rpClientID.orElse(AuditService.UNKNOWN),
                    user,
                    pair(
                            "clientLandingPageUrl",
                            userContext
                                    .getClient()
                                    .map(ClientRegistry::getLandingPageUrl)
                                    .orElse(AuditService.UNKNOWN)),
                    pair("rpPairwiseId", rpPairwiseId));

            LOG.info(
                    "IPVAuthorisationHandler successfully processed request, redirect URI {}",
                    ipvAuthorisationRequest.toURI().toString());
            cloudwatchMetricsService.incrementCounter(
                    "IPVHandoff", Map.of("Environment", configurationService.getEnvironment()));
            return generateApiGatewayProxyResponse(
                    200, new IPVAuthorisationResponse(ipvAuthorisationRequest.toURI().toString()));

        } catch (ParseException | JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        } catch (ClientNotFoundException e) {
            return generateApiGatewayProxyErrorResponse(500, ErrorResponse.ERROR_1015);
        } catch (IPVCallbackNoSessionException e) {
            throw new RuntimeException(e);
        }
    }

    private Optional<ClaimsSetRequest> buildIpvClaimsRequest(AuthenticationRequest authRequest) {
        return Optional.ofNullable(authRequest)
                .map(AuthenticationRequest::getOIDCClaims)
                .map(OIDCClaimsRequest::getUserInfoClaimsRequest);
    }
}
