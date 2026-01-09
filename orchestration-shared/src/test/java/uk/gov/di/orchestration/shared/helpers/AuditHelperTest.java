package uk.gov.di.orchestration.shared.helpers;

import org.apache.logging.log4j.ThreadContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.orchestration.shared.exceptions.InvalidEncodingException;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.orchestration.shared.helpers.AuditHelper.AuditField.TXMA_ENCODED_HEADER;
import static uk.gov.di.orchestration.shared.helpers.AuditHelper.attachAuditField;
import static uk.gov.di.orchestration.shared.helpers.AuditHelper.attachTxmaAuditFieldFromHeaders;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withMessageContaining;

// QualityGateUnitTest
class AuditHelperTest {

    private final String TXMA_ENCODED_HEADER_VALUE = "dGVzdAo=";
    private final String NOT_VALID_BASE64 = "not-@-b@se64-identifier";

    @RegisterExtension
    private final CaptureLoggingExtension logging = new CaptureLoggingExtension(AuditHelper.class);

    @BeforeEach
    void setup() {
        ThreadContext.clearAll();
    }

    // QualityGateRegressionTest
    @Test
    void shouldAttachValidTxmaHeaderToThreadContext() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Txma-Audit-Encoded", TXMA_ENCODED_HEADER_VALUE);

        attachTxmaAuditFieldFromHeaders(headers);

        assertTrue(ThreadContext.containsKey(TXMA_ENCODED_HEADER.getFieldName()));
        assertEquals(1, ThreadContext.getContext().size());
        assertEquals(
                TXMA_ENCODED_HEADER_VALUE, ThreadContext.get(TXMA_ENCODED_HEADER.getFieldName()));
    }

    // QualityGateRegressionTest
    @Test
    void shouldNotAttachMissingTxmaHeaders() {
        Map<String, String> headers = new HashMap<>();
        attachTxmaAuditFieldFromHeaders(headers);

        assertFalse(ThreadContext.containsKey(TXMA_ENCODED_HEADER.getFieldName()));
    }

    // QualityGateRegressionTest
    @Test
    void shouldLogMalformedTxmaHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Txma-Audit-Encoded", NOT_VALID_BASE64);
        attachTxmaAuditFieldFromHeaders(headers);

        assertFalse(ThreadContext.containsKey(TXMA_ENCODED_HEADER.getFieldName()));
        assertThat(
                logging.events(),
                hasItem(withMessageContaining("Audit field has invalid base64url encoding")));
    }

    // QualityGateRegressionTest
    @Test
    void shouldAttachAuditFieldToThreadContextUsingAttachAuditField()
            throws InvalidEncodingException {
        attachAuditField(TXMA_ENCODED_HEADER, TXMA_ENCODED_HEADER_VALUE);

        assertTrue(ThreadContext.containsKey(TXMA_ENCODED_HEADER.getFieldName()));
        assertEquals(1, ThreadContext.getContext().size());
        assertEquals(
                TXMA_ENCODED_HEADER_VALUE, ThreadContext.get(TXMA_ENCODED_HEADER.getFieldName()));
    }

    // QualityGateRegressionTest
    @Test
    void shouldHandleBlankAuditField() {
        assertThrows(
                InvalidEncodingException.class, () -> attachAuditField(TXMA_ENCODED_HEADER, ""));
    }

    // QualityGateRegressionTest
    @Test
    void shouldHandleNullAuditField() {
        assertThrows(
                InvalidEncodingException.class, () -> attachAuditField(TXMA_ENCODED_HEADER, null));
    }

    // QualityGateRegressionTest
    @Test
    void shouldThrowIfEncodingIsWrong() {

        assertThrows(
                InvalidEncodingException.class,
                () -> attachAuditField(TXMA_ENCODED_HEADER, NOT_VALID_BASE64));
    }
}
