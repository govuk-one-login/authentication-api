package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.sharedtest.extensions.IDReverificationStateExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IDReverificationStateServiceIntegrationTest {
    @RegisterExtension
    protected static final IDReverificationStateExtension idReverificationStateExtension =
            new IDReverificationStateExtension();

    @Test
    void shouldStoreValuesCorrectly() {
        idReverificationStateExtension.store("orch-redirect-url", "client-session-id");

        var result = idReverificationStateExtension.getIDReverificationState();

        assertTrue(result.isPresent());
        assertEquals("orch-redirect-url", result.get().getOrchestrationRedirectUrl());
        assertEquals("client-session-id", result.get().getClientSessionId());
    }
}
