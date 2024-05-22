package uk.gov.di.orchestration.shared.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.orchestration.shared.exceptions.InvalidEncodingException;

import java.util.Map;

import static uk.gov.di.orchestration.shared.helpers.AuditHelper.AuditField.TXMA_ENCODED_HEADER;
import static uk.gov.di.orchestration.shared.helpers.InputSanitiser.sanitiseBase64;

public class AuditHelper {

    private static final Logger LOG = LogManager.getLogger(AuditHelper.class);

    public enum AuditField {
        TXMA_ENCODED_HEADER("txmaEncodedHeader", true);

        private final String fieldName;
        private boolean isBase64;

        AuditField(String fieldName, boolean isBase64) {
            this.fieldName = fieldName;
            this.isBase64 = isBase64;
        }

        public String getFieldName() {
            return fieldName;
        }
    }

    public static void attachTxmaAuditFieldFromHeaders(Map<String, String> headers) {
        try {
            var txmaEncoded =
                    RequestHeaderHelper.getHeaderValueFromHeaders(headers, "txma-audit-encoded");
            if (txmaEncoded != null) {
                attachAuditField(TXMA_ENCODED_HEADER, txmaEncoded);
            }
        } catch (InvalidEncodingException e) {
            LOG.error(e.getMessage());
        }
    }

    public static void attachAuditField(AuditField auditField, String value)
            throws InvalidEncodingException {
        if (value == null || value.isEmpty()) {
            throw new InvalidEncodingException("Audit field cannot be empty");
        } else if (auditField.isBase64 && sanitiseBase64(value).isEmpty()) {
            throw new InvalidEncodingException("Audit field has invalid base64url encoding");
        } else {
            ThreadContext.put(auditField.getFieldName(), value);
        }
    }
}
