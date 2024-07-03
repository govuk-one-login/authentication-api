package uk.gov.di.accountmanagement.helpers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.accountmanagement.helpers.AuditHelper.TXMA_ENCODED_HEADER_NAME;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class AuditHelperTest {

    @RegisterExtension
    public final CaptureLoggingExtension logging = new CaptureLoggingExtension(AuditHelper.class);

    @Test
    void restrictedSectionPopulatedWithValidHeader() {
        String auditValue = "validHeaderValue";
        AuditService.RestrictedSection restrictedSection =
                AuditHelper.buildRestrictedSection(Map.of(TXMA_ENCODED_HEADER_NAME, auditValue));
        assertEquals(restrictedSection.encoded().get(), auditValue);
    }

    @Test
    void warningLoggedWhenMissingHeader() {
        AuditService.RestrictedSection restrictedSection =
                AuditHelper.buildRestrictedSection(Map.of());
        assertEquals(restrictedSection, AuditService.RestrictedSection.empty);
        assertThat(
                logging.events(),
                hasItem(withMessageContaining("Audit header field value cannot be empty")));
    }

    @Test
    void warningLoggedWheEmptyHeader() {
        AuditService.RestrictedSection restrictedSection =
                AuditHelper.buildRestrictedSection(Map.of(TXMA_ENCODED_HEADER_NAME, ""));
        assertEquals(restrictedSection, AuditService.RestrictedSection.empty);
        assertThat(
                logging.events(),
                hasItem(withMessageContaining("Audit header field value cannot be empty")));
    }

    @Test
    void shouldRetrieveATxmaAuditEncodedFieldFromAHeader() {
        String auditValue = "validHeaderValue";
        var result = AuditHelper.getTxmaAuditEncoded(Map.of(TXMA_ENCODED_HEADER_NAME, auditValue));
        assertEquals(Optional.of(auditValue), result);
    }

    @Test
    void shouldLogAwarningWhenMissingHeader() {
        var result = AuditHelper.getTxmaAuditEncoded(Map.of());
        assertEquals(Optional.empty(), result);
        assertThat(
                logging.events(),
                hasItem(withMessageContaining("Audit header field value cannot be empty")));
    }

    @Test
    void shouldLogAWarningWhenEmptyHeader() {
        var result = AuditHelper.getTxmaAuditEncoded(Map.of(TXMA_ENCODED_HEADER_NAME, ""));
        assertEquals(Optional.empty(), result);
        assertThat(
                logging.events(),
                hasItem(withMessageContaining("Audit header field value cannot be empty")));
    }
}
