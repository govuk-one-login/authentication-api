package uk.gov.di.orchestration.identity.service;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import uk.gov.di.orchestration.identity.entity.CrossBrowserNoSessionException;
import uk.gov.di.orchestration.identity.entity.IdentityContext;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.exceptions.NoSessionException;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.services.CrossBrowserOrchestrationService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;

import java.util.Objects;

import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachSessionIdToLogs;

public class IdentityContextService {
    private final CrossBrowserOrchestrationService crossBrowserOrchestrationService;
    private final OrchSessionService orchSessionService;

    public IdentityContextService(
            CrossBrowserOrchestrationService crossBrowserOrchestrationService,
            OrchSessionService orchSessionService) {
        this.crossBrowserOrchestrationService = crossBrowserOrchestrationService;
        this.orchSessionService = orchSessionService;
    }

    public IdentityContext buildContext(APIGatewayProxyRequestEvent input)
            throws CrossBrowserNoSessionException, NoSessionException {
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
        return null;
    }
}
