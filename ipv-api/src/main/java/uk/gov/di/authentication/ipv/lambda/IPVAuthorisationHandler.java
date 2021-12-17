package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.entity.IPVAuthorisationRequest;
import uk.gov.di.authentication.ipv.entity.IPVAuthorisationResponse;
import uk.gov.di.authentication.ipv.services.IPVAuthorisationService;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.StateMachine;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.authentication.shared.entity.SessionState.IPV_REQUIRED;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.shared.state.StateMachine.userJourneyStateMachine;

public class IPVAuthorisationHandler extends BaseFrontendHandler<IPVAuthorisationRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(IPVAuthorisationHandler.class);

    private static final String IPV_AUTHORIZE_ROUTE = "/authorize";
    private final AuditService auditService;
    private final IPVAuthorisationService authorisationService;
    private final StateMachine<SessionState, SessionAction, UserContext> stateMachine =
            userJourneyStateMachine();

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
                        configurationService, new RedisConnectionService(configurationService));
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            IPVAuthorisationRequest request,
            UserContext userContext) {
        try {
            LOG.info("IPVAuthorisationHandler received request");
            var authRequest =
                    AuthenticationRequest.parse(
                            userContext.getClientSession().getAuthRequestParams());

            var clientID = new ClientID(configurationService.getIPVAuthorisationClientId());
            var state = new State();
            Optional<ClaimsSetRequest> claimsSetRequest = buildIpvClaimsRequest(authRequest);
            var authRequestBuilder =
                    new AuthorizationRequest.Builder(
                                    new ResponseType(ResponseType.Value.CODE), clientID)
                            .scope(authRequest.getScope())
                            .customParameter("nonce", IdGenerator.generate())
                            .state(state)
                            .redirectionURI(configurationService.getIPVAuthorisationCallbackURI())
                            .endpointURI(
                                    buildURI(
                                            configurationService
                                                    .getIPVAuthorisationURI()
                                                    .toString(),
                                            IPV_AUTHORIZE_ROUTE));
            claimsSetRequest.ifPresent(
                    t -> authRequestBuilder.customParameter("claims", t.toJSONString()));

            var ipvAuthorisationRequest = authRequestBuilder.build();
            authorisationService.storeState(userContext.getSession().getSessionId(), state);
            auditService.submitAuditEvent(
                    IPVAuditableEvent.IPV_AUTHORISATION_REQUESTED,
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

            LOG.info(
                    "IPVAuthorisationHandler successfully processed request, redirect URI {}",
                    ipvAuthorisationRequest.toURI().toString());

            return generateApiGatewayProxyResponse(
                    200,
                    new IPVAuthorisationResponse(
                            IPV_REQUIRED, ipvAuthorisationRequest.toURI().toString()));

        } catch (StateMachine.InvalidStateTransitionException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1017);
        } catch (ParseException | JsonProcessingException e) {
            LOG.error("Could not parse authentication request from client");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }

    private Optional<ClaimsSetRequest> buildIpvClaimsRequest(AuthenticationRequest authRequest) {
        if (authRequest.getOIDCClaims() == null
                || authRequest.getOIDCClaims().getUserInfoClaimsRequest() == null) {
            return Optional.empty();
        }
        return Optional.of(authRequest.getOIDCClaims().getUserInfoClaimsRequest());
    }
}
