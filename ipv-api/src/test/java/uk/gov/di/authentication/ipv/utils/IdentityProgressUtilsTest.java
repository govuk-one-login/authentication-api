package uk.gov.di.authentication.ipv.utils;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.ipv.entity.ProcessingIdentityStatus;
import uk.gov.di.orchestration.shared.entity.OrchIdentityCredentials;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.ipv.utils.IdentityProgressUtils.getProcessingIdentityStatus;

class IdentityProgressUtilsTest {
    @Test
    void shouldReturnCompletedStatusWhenIdentityCredentialsPresentWithCoreIdentityJwt() {
        assertEquals(
                ProcessingIdentityStatus.COMPLETED,
                getProcessingIdentityStatus(credentialsCompleted(), 1));
    }

    @Test
    void shouldReturnNoEntryWhenIdentityCredentialsMissingOnFirstAttempt() {
        assertEquals(
                ProcessingIdentityStatus.NO_ENTRY,
                getProcessingIdentityStatus(credentialsNotFound(), 1));
    }

    @Test
    void shouldReturnErrorWhenIdentityCredentialsMissingOnSecondAttempt() {
        assertEquals(
                ProcessingIdentityStatus.ERROR,
                getProcessingIdentityStatus(credentialsNotFound(), 2));
    }

    @Test
    void shouldReturnProcessingWhenIdentityCredentialsPresentButMissingCoreIdentityJwt() {
        assertEquals(
                ProcessingIdentityStatus.PROCESSING,
                getProcessingIdentityStatus(credentialsProcessing(), 1));
    }

    private static Optional<OrchIdentityCredentials> credentialsNotFound() {
        return Optional.empty();
    }

    private static Optional<OrchIdentityCredentials> credentialsProcessing() {
        return Optional.of(new OrchIdentityCredentials());
    }

    private static Optional<OrchIdentityCredentials> credentialsCompleted() {
        return Optional.of(new OrchIdentityCredentials().withCoreIdentityJWT("test-jwt"));
    }
}
