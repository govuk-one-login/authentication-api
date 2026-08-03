package uk.gov.di.orchestration.sis.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.ipv.services.InitiateIPVAuthorisationService;
import uk.gov.di.orchestration.audit.AuditContext;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.identity.entity.CrossBrowserNoSessionException;
import uk.gov.di.orchestration.identity.entity.CrossBrowserStateMismatchException;
import uk.gov.di.orchestration.identity.entity.IdentityContext;
import uk.gov.di.orchestration.identity.exceptions.IdentityCallbackException;
import uk.gov.di.orchestration.identity.helpers.IdentityCallbackHelper;
import uk.gov.di.orchestration.identity.service.IdentityContextService;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.NoSessionException;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.helpers.IpAddressHelper;
import uk.gov.di.orchestration.shared.helpers.PersistentIdHelper;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.EndOfJourneyService;
import uk.gov.di.orchestration.sis.service.SISAuthorisationService;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static com.nimbusds.oauth2.sdk.OAuth2Error.ACCESS_DENIED_CODE;
import static uk.gov.di.orchestration.shared.entity.ValidClaims.RETURN_CODE;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.AuditHelper.attachTxmaAuditFieldFromHeaders;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.AWS_REQUEST_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachTraceId;
import static uk.gov.di.orchestration.sis.domain.SISAuditableEvent.AUTH_AUTH_CODE_ISSUED;
import static uk.gov.di.orchestration.sis.domain.SISAuditableEvent.ORCH_SIS_SUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED;
import static uk.gov.di.orchestration.sis.domain.SISAuditableEvent.ORCH_SIS_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED;
import static uk.gov.di.orchestration.sis.domain.SISAuditableEvent.ORCH_SIS_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED;
import static uk.gov.di.orchestration.sis.domain.SISAuditableEvent.ORCH_SIS_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED;
import static uk.gov.di.orchestration.sis.domain.SISAuditableEvent.ORCH_SIS_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED;

public class SISCallbackHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOG = LogManager.getLogger(SISCallbackHandler.class);
    private final ConfigurationService configurationService;
    private final IdentityCallbackHelper identityCallbackHelper;
    private final IdentityContextService identityContextService;
    private final AuditService auditService;
    private final EndOfJourneyService endOfJourneyService;
    private final SISAuthorisationService sisAuthorisationService;
    private final InitiateIPVAuthorisationService ipvAuthorisationService;

    public SISCallbackHandler(
            ConfigurationService configurationService,
            IdentityCallbackHelper identityCallbackHelper,
            IdentityContextService identityContextService,
            AuditService auditService,
            EndOfJourneyService endOfJourneyService,
            SISAuthorisationService sisAuthorisationService,
            InitiateIPVAuthorisationService ipvAuthorisationService) {
        this.configurationService = configurationService;
        this.identityCallbackHelper = identityCallbackHelper;
        this.identityContextService = identityContextService;
        this.auditService = auditService;
        this.endOfJourneyService = endOfJourneyService;
        this.sisAuthorisationService = sisAuthorisationService;
        this.ipvAuthorisationService = ipvAuthorisationService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        ThreadContext.clearMap();
        attachTraceId();
        attachLogFieldToLogs(AWS_REQUEST_ID, context.getAwsRequestId());
        LOG.info("Request received to SISCallbackHandler");
        attachTxmaAuditFieldFromHeaders(input.getHeaders());
        try {
            if (!configurationService.isIdentityEnabled()) {
                throw new IdentityCallbackException("Identity is not enabled");
            }
            var identityContextResponse = getIdentityContext(input);
            if (identityContextResponse.earlyRedirect != null) {
                return identityContextResponse.earlyRedirect;
            }
            var identityContext = identityContextResponse.identityContext;
            var orchSession = identityContext.orchSessionItem();
            var sessionId = orchSession.getSessionId();
            var orchClientSession = identityContext.orchClientSessionItem();
            var clientSessionId = orchClientSession.getClientSessionId();
            var clientRegistry = identityContext.clientRegistry();
            var clientId = clientRegistry.getClientID();
            var authUserInfo = identityContext.authUserInfo();
            var authRequest = identityContext.authRequest();

            var persistentId =
                    PersistentIdHelper.extractPersistentIdFromCookieHeader(input.getHeaders());
            var ipAddress = IpAddressHelper.extractIpAddress(input);
            var auditContext =
                    new AuditContext(
                            clientSessionId,
                            sessionId,
                            clientId,
                            orchSession.getInternalCommonSubjectId(),
                            authUserInfo.getEmailAddress(),
                            ipAddress,
                            Objects.isNull(authUserInfo.getPhoneNumber())
                                    ? AuditService.UNKNOWN
                                    : authUserInfo.getPhoneNumber(),
                            persistentId);

            var user =
                    TxmaAuditUser.user()
                            .withGovukSigninJourneyId(clientSessionId)
                            .withSessionId(sessionId)
                            .withUserId(orchSession.getInternalCommonSubjectId())
                            .withEmail(authUserInfo.getEmailAddress())
                            .withPhone(
                                    Objects.isNull(authUserInfo.getPhoneNumber())
                                            ? AuditService.UNKNOWN
                                            : authUserInfo.getPhoneNumber())
                            .withPersistentSessionId(persistentId);

            var validationRedirectOpt =
                    validateAuthResponse(input, identityContext, auditContext, user);
            if (validationRedirectOpt.isPresent()) {
                return validationRedirectOpt.get();
            }
            auditService.submitAuditEventNoPrefix(
                    ORCH_SIS_SUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED, clientId, user);

            var authCode = input.getQueryStringParameters().get("code");
            var tokenResponse = makeTokenRequest(authCode, clientId, user);
            auditService.submitAuditEventNoPrefix(
                    ORCH_SIS_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED, clientId, user);

            var userIdentityUserInfo =
                    identityCallbackHelper.sendUserIdentityRequest(
                            tokenResponse, configurationService.getSISBackendURI());
            auditService.submitAuditEventNoPrefix(
                    ORCH_SIS_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED, clientId, user);

            var redirect =
                    validateUserIdentityResponse(
                            userIdentityUserInfo, identityContext, auditContext, user);
            if (redirect.isPresent()) {
                return redirect.get();
            }
        } catch (IdentityCallbackException e) {
            return identityCallbackHelper.redirectToFrontendErrorPageWithErrorLog(e);
        } catch (NoSessionException e) {
            return identityCallbackHelper.redirectToFrontendErrorPageForNoSession(e);
        } catch (ParseException e) {
            return identityCallbackHelper.redirectToFrontendErrorPageWithErrorLog(
                    new Error("Cannot retrieve auth request params from client session id"));
        } catch (UnsuccessfulCredentialResponseException e) {
            return identityCallbackHelper.redirectToFrontendErrorPageWithWarnLog(e);
        }
        return null;
    }

    private TokenResponse makeTokenRequest(String authCode, String clientId, TxmaAuditUser user)
            throws IdentityCallbackException {
        try {
            return identityCallbackHelper.makeTokenRequest(authCode);
        } catch (IdentityCallbackException e) {
            auditService.submitAuditEventNoPrefix(
                    ORCH_SIS_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED, clientId, user);
            throw e;
        }
    }

    private IdentityContextResponse getIdentityContext(APIGatewayProxyRequestEvent input)
            throws ParseException, NoSessionException, IdentityCallbackException {
        try {
            return new IdentityContextResponse(identityContextService.buildContext(input), null);
        } catch (CrossBrowserStateMismatchException | CrossBrowserNoSessionException e) {
            var authRequest =
                    AuthenticationRequest.parse(
                            e.getEntity().getClientSession().getAuthRequestParams());
            attachLogFieldToLogs(CLIENT_ID, authRequest.getClientID().getValue());
            auditService.submitAuditEventNoPrefix(
                    ORCH_SIS_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED,
                    authRequest.getClientID().getValue(),
                    TxmaAuditUser.user()
                            .withGovukSigninJourneyId(e.getEntity().getClientSessionId())
                            .withSessionId(AuditService.UNKNOWN));

            var additionalLog =
                    "No Session Error: " + (e instanceof CrossBrowserNoSessionException);
            return new IdentityContextResponse(
                    null,
                    endOfJourneyService.generateAuthenticationErrorResponse(
                            authRequest, e.getEntity().getErrorObject(), additionalLog));
        }
    }

    private record IdentityContextResponse(
            IdentityContext identityContext, APIGatewayProxyResponseEvent earlyRedirect) {}

    private Optional<APIGatewayProxyResponseEvent> validateAuthResponse(
            APIGatewayProxyRequestEvent input,
            IdentityContext identityContext,
            AuditContext auditContext,
            TxmaAuditUser user) {
        var validationErrorOpt =
                segmentedFunctionCall(
                        "validateSISAuthResponse",
                        () ->
                                sisAuthorisationService.validateResponse(
                                        input.getQueryStringParameters(),
                                        identityContext.orchSessionItem().getSessionId()));

        if (validationErrorOpt.isPresent()) {
            auditService.submitAuditEventNoPrefix(
                    ORCH_SIS_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED,
                    identityContext.clientRegistry().getClientID(),
                    user);
            var validationError = validationErrorOpt.get();
            if (validationError.userShouldRouteToIpv()) {
                return Optional.ofNullable(
                        ipvAuthorisationService.sendRequestToIPV(
                                input,
                                identityContext.authRequest(),
                                identityContext.authUserInfo(),
                                identityContext.orchSessionItem().getSessionId(),
                                identityContext.clientRegistry(),
                                identityContext.clientRegistry().getClientID(),
                                identityContext.orchClientSessionItem().getClientSessionId(),
                                auditContext.persistentSessionId(),
                                false,
                                VectorOfTrust.getRequestedLevelsOfConfidence(
                                        identityContext.orchClientSessionItem().getVtrList()),
                                validationError.userRequestedUpdate()));
            }
            var aisIntervention =
                    endOfJourneyService.getAndCheckForIntervention(
                            identityContext.orchSessionItem(),
                            auditContext,
                            user,
                            identityContext.clientRegistry().getClientID(),
                            false);
            if (aisIntervention.isPresent()) {
                return aisIntervention;
            }
            return Optional.ofNullable(
                    endOfJourneyService.generateAuthenticationErrorResponse(
                            identityContext.authRequest(),
                            new ErrorObject(
                                    ACCESS_DENIED_CODE, validationError.errorDescription())));
        }
        return Optional.empty();
    }

    private static boolean returnCodePresentInIdentityResponse(Object returnCode) {
        return returnCode instanceof List<?> returnCodeList && !returnCodeList.isEmpty();
    }

    private static boolean rpRequestedReturnCode(
            ClientRegistry clientRegistry, AuthenticationRequest authRequest) {
        if (authRequest.getOIDCClaims() == null
                || authRequest.getOIDCClaims().getUserInfoClaimsRequest() == null) {
            return false;
        }
        return clientRegistry.getClaims().contains(RETURN_CODE.getValue())
                && authRequest
                                .getOIDCClaims()
                                .getUserInfoClaimsRequest()
                                .get(RETURN_CODE.getValue())
                        != null;
    }

    private Optional<APIGatewayProxyResponseEvent> validateUserIdentityResponse(
            UserInfo userIdentityUserInfo,
            IdentityContext identityContext,
            AuditContext auditContext,
            TxmaAuditUser user)
            throws IdentityCallbackException {
        var locList =
                identityContext.orchClientSessionItem().getVtrList().stream()
                        .map(VectorOfTrust::getLevelOfConfidence)
                        .filter(Objects::nonNull)
                        .toList();
        var rpPairwiseSubject =
                new Subject(identityContext.orchClientSessionItem().getRpPairwiseId());
        var userIdentityError =
                identityCallbackHelper.validateUserIdentityResponse(userIdentityUserInfo, locList);
        if (userIdentityError.isPresent()) {
            var aisResponseOpt =
                    endOfJourneyService.getAndCheckForIntervention(
                            identityContext.orchSessionItem(),
                            auditContext,
                            user,
                            identityContext.clientRegistry().getClientID(),
                            false);
            if (aisResponseOpt.isPresent()) {
                return aisResponseOpt;
            }
            var error = userIdentityError.get();
            var returnCode = userIdentityUserInfo.getClaim(RETURN_CODE.getValue());
            if (returnCodePresentInIdentityResponse(returnCode)) {
                if (rpRequestedReturnCode(
                        identityContext.clientRegistry(), identityContext.authRequest())) {
                    LOG.info("Generating auth code response for return code(s)");
                    segmentedFunctionCall(
                            "saveIdentityClaims",
                            () ->
                                    identityCallbackHelper.saveIdentityClaimsToDynamo(
                                            identityContext
                                                    .orchClientSessionItem()
                                                    .getClientSessionId(),
                                            rpPairwiseSubject,
                                            userIdentityUserInfo,
                                            null));
                    var authenticationResponse =
                            endOfJourneyService.generateSuccessfulAuthResponse(
                                    identityContext.authRequest(),
                                    identityContext.clientRegistry().getClientID(),
                                    identityContext.orchClientSessionItem().getClientSessionId(),
                                    identityContext.authUserInfo().getEmailAddress(),
                                    identityContext.orchSessionItem());
                    auditService.submitAuditEventNoPrefix(
                            AUTH_AUTH_CODE_ISSUED,
                            identityContext.clientRegistry().getClientID(),
                            user);
                    // TODO: send cloudwatch metrics for sis journey completed
                    return Optional.ofNullable(
                            generateApiGatewayProxyResponse(
                                    302,
                                    "",
                                    Map.of(
                                            ResponseHeaders.LOCATION,
                                            authenticationResponse.toURI().toString()),
                                    null));
                } else {
                    error = OAuth2Error.ACCESS_DENIED;
                }
            }
            LOG.warn("SPOT will not be invoked. Returning Error to RP");
            var errorResponse =
                    new AuthenticationErrorResponse(
                            identityContext.authRequest().getRedirectionURI(),
                            error,
                            identityContext.authRequest().getState(),
                            identityContext.authRequest().getResponseMode());
            return Optional.ofNullable(
                    generateApiGatewayProxyResponse(
                            302,
                            "",
                            Map.of(ResponseHeaders.LOCATION, errorResponse.toURI().toString()),
                            null));
        }
        return Optional.empty();
    }
}
