package uk.gov.di.authentication.shared.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getOptionalHeaderValueFromHeaders;

public class TxmaAuditHelper {
    private static final Logger LOG = LogManager.getLogger(TxmaAuditHelper.class);
    public static final String TXMA_AUDIT_ENCODED_HEADER = "txma-audit-encoded";

    private TxmaAuditHelper() {}

    public static Optional<String> getTxmaAuditEncodedHeader(APIGatewayProxyRequestEvent request) {
        return getOptionalHeaderValueFromHeaders(
                request.getHeaders(), TXMA_AUDIT_ENCODED_HEADER, false);
    }

    public static String getRpPairwiseId(
            AuthenticationService authenticationService,
            ConfigurationService configurationService,
            UserContext userContext) {
        LOG.info("Calculating RP pairwise identifier");

        var userProfile = userContext.getUserProfile();
        var client = userContext.getClient();

        if (userProfile.isEmpty() || client.isEmpty()) {
            LOG.warn("Returning empty RP pairwise identifier - no user profile or client found");
            return AuditService.UNKNOWN;
        }

        return ClientSubjectHelper.getSubject(
                        userProfile.get(),
                        client.get(),
                        authenticationService,
                        configurationService.getInternalSectorUri())
                .toString();
    }
}
