package uk.gov.di.orchestration.identity.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.identity.entity.AuditEventConfiguration;
import uk.gov.di.orchestration.identity.service.IdentityTokenService;
import uk.gov.di.orchestration.shared.api.CommonFrontend;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.RedirectService;

import java.util.Optional;

import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class IdentityCallbackHelper {
    private final IdentityTokenService identityTokenService;
    private final AuditService auditService;
    private final AuditEventConfiguration auditEventConfiguration;
    private final CommonFrontend frontend;

    public IdentityCallbackHelper(
            IdentityTokenService identityTokenService,
            AuditService auditService,
            AuditEventConfiguration auditEventConfiguration,
            CommonFrontend frontend) {
        this.identityTokenService = identityTokenService;
        this.auditService = auditService;
        this.auditEventConfiguration = auditEventConfiguration;
        this.frontend = frontend;
    }

    public Optional<APIGatewayProxyResponseEvent> makeTokenRequest(
            String authCode, String clientId, TxmaAuditUser user) {
        var tokenResponse =
                segmentedFunctionCall("getToken", () -> identityTokenService.getToken(authCode));
        if (!tokenResponse.indicatesSuccess()) {
            auditService.submitAuditEvent(
                    auditEventConfiguration.unsuccessfulTokenResponseReceived(), clientId, user);
            return Optional.of(
                    RedirectService.redirectToFrontendErrorPageWithErrorLog(
                            frontend.errorURI(),
                            new Exception(
                                    String.format(
                                            "TokenResponse was not successful: %s",
                                            tokenResponse.toErrorResponse().toJSONObject()))));
        }
        auditService.submitAuditEvent(
                auditEventConfiguration.successfulTokenResponseReceived(), clientId, user);
        return Optional.empty();
    }
}
