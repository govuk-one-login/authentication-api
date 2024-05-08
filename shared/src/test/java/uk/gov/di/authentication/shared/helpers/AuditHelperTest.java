package uk.gov.di.authentication.shared.helpers;

import org.apache.logging.log4j.ThreadContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.helpers.AuditHelper.AuditField;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class AuditHelperTest {

    @Test
    void auditFieldAttachedToThreadContextWithValidValue() {
        String auditValue = "validHeaderValue";
        AuditHelper.attachTxmaAuditFieldFromHeaders(
                Map.of(AuditField.TXMA_ENCODED_HEADER.getHeaderName(), auditValue));
        assertEquals(ThreadContext.get(AuditField.TXMA_ENCODED_HEADER.getFieldName()), auditValue);
    }

    @Test
    void auditFieldHeaderMissing() {
        AuditHelper.attachTxmaAuditFieldFromHeaders(Map.of());
        assertNull(ThreadContext.get(AuditField.TXMA_ENCODED_HEADER.getFieldName()));
    }

    @Test
    void auditFieldValueNotSet() {
        AuditHelper.attachTxmaAuditFieldFromHeaders(
                Map.of(AuditField.TXMA_ENCODED_HEADER.getHeaderName(), ""));
        assertNull(ThreadContext.get(AuditField.TXMA_ENCODED_HEADER.getFieldName()));
    }

    @Test
    void auditFieldHasInvalidEncoding() {
        AuditHelper.attachTxmaAuditFieldFromHeaders(
                Map.of(AuditField.TXMA_ENCODED_HEADER.getHeaderName(), "AAAA\\0"));
        assertNull(ThreadContext.get(AuditField.TXMA_ENCODED_HEADER.getFieldName()));
    }

    @AfterEach
    public void cleanup() {
        ThreadContext.clearMap();
    }
}
