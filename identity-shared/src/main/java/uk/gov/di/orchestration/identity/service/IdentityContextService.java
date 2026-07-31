package uk.gov.di.orchestration.identity.service;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import uk.gov.di.orchestration.identity.entity.CrossBrowserNoSessionException;
import uk.gov.di.orchestration.identity.entity.IdentityContext;
import uk.gov.di.orchestration.shared.exceptions.NoSessionException;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.services.CrossBrowserOrchestrationService;

import java.util.Objects;

public class IdentityContextService {
    private final CrossBrowserOrchestrationService crossBrowserOrchestrationService;

    public IdentityContextService(
            CrossBrowserOrchestrationService crossBrowserOrchestrationService) {
        this.crossBrowserOrchestrationService = crossBrowserOrchestrationService;
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
        return null;
    }
}
