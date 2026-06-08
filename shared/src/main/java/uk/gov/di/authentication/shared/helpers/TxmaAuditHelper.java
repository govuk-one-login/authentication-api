package uk.gov.di.authentication.shared.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.services.AuditService;

import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getOptionalHeaderValueFromHeaders;

public class TxmaAuditHelper {
    private static final Logger LOG = LogManager.getLogger(TxmaAuditHelper.class);
    public static final String TXMA_AUDIT_ENCODED_HEADER = "txma-audit-encoded";

    private TxmaAuditHelper() {}

    public static String getTxmaAuditEncodedHeaderOrUnknown(APIGatewayProxyRequestEvent request) {
        Optional<String> header =
                getOptionalHeaderValueFromHeaders(
                        request.getHeaders(), TXMA_AUDIT_ENCODED_HEADER, false);
        if (header.isEmpty()) {
            LOG.warn("Encoded device information for audit event is not present.");
            return AuditService.UNKNOWN;
        }
        if (header.get().isEmpty()) {
            LOG.warn("Encoded device information for audit event present but empty.");
            return AuditService.UNKNOWN;
        }
        return header.get();
    }
}
