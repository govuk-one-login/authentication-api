package uk.gov.di.accountmanagement.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.services.AuditService;

import java.util.Map;
import java.util.Optional;

public class AuditHelper {

    private static final Logger LOG = LogManager.getLogger(AuditHelper.class);
    public static final String TXMA_ENCODED_HEADER_NAME = "txma-audit-encoded";

    public static AuditService.RestrictedSection buildRestrictedSection(
            Map<String, String> headers) {
        String txmaEncodedValue =
                RequestHeaderHelper.getHeaderValueFromHeaders(
                        headers, TXMA_ENCODED_HEADER_NAME, false);
        if (txmaEncodedValue != null && !txmaEncodedValue.isEmpty()) {
            return new AuditService.RestrictedSection(Optional.of(txmaEncodedValue));
        } else {
            LOG.warn("Audit header field value cannot be empty");
            return AuditService.RestrictedSection.empty;
        }
    }

    public static Optional<String> getTxmaAuditEncoded(Map<String, String> headers) {
        String txmaEncodedValue =
                RequestHeaderHelper.getHeaderValueFromHeaders(
                        headers, TXMA_ENCODED_HEADER_NAME, false);
        if (txmaEncodedValue != null && !txmaEncodedValue.isEmpty()) {
            return Optional.of(txmaEncodedValue);
        } else {
            LOG.warn("Audit header field value cannot be empty");
            return Optional.empty();
        }
    }
}
