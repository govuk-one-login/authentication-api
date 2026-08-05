package uk.gov.di.orchestration.identity.service;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import uk.gov.di.orchestration.identity.entity.CrossBrowserNoSessionException;
import uk.gov.di.orchestration.identity.entity.CrossBrowserStateMismatchException;
import uk.gov.di.orchestration.identity.entity.IdentityContext;
import uk.gov.di.orchestration.identity.exceptions.IdentityCallbackException;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.exceptions.NoSessionException;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.helpers.PersistentIdHelper;
import uk.gov.di.orchestration.shared.services.AuthenticationUserInfoStorageService;
import uk.gov.di.orchestration.shared.services.CrossBrowserOrchestrationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.OrchClientSessionService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;

import java.util.Objects;

import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachSessionIdToLogs;

public class IdentityContextService {
    private final CrossBrowserOrchestrationService crossBrowserOrchestrationService;
    private final OrchSessionService orchSessionService;
    private final OrchClientSessionService orchClientSessionService;
    private final DynamoClientService clientService;
    private final AuthenticationUserInfoStorageService authUserInfoStorageService;

    public IdentityContextService(
            CrossBrowserOrchestrationService crossBrowserOrchestrationService,
            OrchSessionService orchSessionService,
            OrchClientSessionService orchClientSessionService,
            DynamoClientService clientService,
            AuthenticationUserInfoStorageService authUserInfoStorageService) {
        this.crossBrowserOrchestrationService = crossBrowserOrchestrationService;
        this.orchSessionService = orchSessionService;
        this.orchClientSessionService = orchClientSessionService;
        this.clientService = clientService;
        this.authUserInfoStorageService = authUserInfoStorageService;
    }

    public IdentityContext buildContext(APIGatewayProxyRequestEvent input)
            throws CrossBrowserNoSessionException,
                    NoSessionException,
                    CrossBrowserStateMismatchException,
                    ParseException,
                    IdentityCallbackException {
        var sessionCookiesIds = CookieHelper.parseSessionCookie(input.getHeaders()).orElse(null);
        if (Objects.isNull(sessionCookiesIds)) {
            var noSessionEntity =
                    crossBrowserOrchestrationService.generateNoSessionOrchestrationEntity(
                            input.getQueryStringParameters());
            throw new CrossBrowserNoSessionException(noSessionEntity);
        }

        var sessionId = sessionCookiesIds.getSessionId();
        OrchSessionItem orchSession =
                orchSessionService
                        .getSession(sessionId)
                        .orElseThrow(
                                () ->
                                        new NoSessionException(
                                                "Orchestration session not found in DynamoDB"));
        attachSessionIdToLogs(sessionId);

        var persistentId =
                PersistentIdHelper.extractPersistentIdFromCookieHeader(input.getHeaders());
        attachLogFieldToLogs(PERSISTENT_SESSION_ID, persistentId);
        var clientSessionId = sessionCookiesIds.getClientSessionId();
        attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);
        attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, clientSessionId);
        var orchClientSession =
                orchClientSessionService
                        .getClientSession(clientSessionId)
                        .orElseThrow(() -> new NoSessionException("ClientSession not found"));

        var mismatchedEntity =
                crossBrowserOrchestrationService.generateEntityForMismatchInClientSessionId(
                        input.getQueryStringParameters(), clientSessionId, orchSession);
        if (mismatchedEntity.isPresent()) {
            throw new CrossBrowserStateMismatchException(mismatchedEntity.get());
        }

        var authRequest = AuthenticationRequest.parse(orchClientSession.getAuthRequestParams());
        var clientId = authRequest.getClientID().getValue();
        attachLogFieldToLogs(CLIENT_ID, clientId);

        var clientRegistry =
                clientService
                        .getClient(clientId)
                        .orElseThrow(
                                () ->
                                        new IdentityCallbackException(
                                                "Client registry not found with given clientId"));

        var authUserInfo =
                authUserInfoStorageService
                        .getAuthenticationUserInfo(
                                orchSession.getInternalCommonSubjectId(), clientSessionId)
                        .orElseThrow(() -> new IdentityCallbackException("authUserInfo not found"));
        return new IdentityContext(
                orchSession, orchClientSession, clientRegistry, authUserInfo, authRequest);
    }
}
