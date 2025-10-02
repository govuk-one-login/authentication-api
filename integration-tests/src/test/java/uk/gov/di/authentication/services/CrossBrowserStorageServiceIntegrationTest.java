package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.orchestration.sharedtest.extensions.CrossBrowserStorageExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.orchestration.sharedtest.helper.Constants.CLIENT_SESSION_ID;
import static uk.gov.di.orchestration.sharedtest.helper.Constants.STATE;

class CrossBrowserStorageServiceIntegrationTest {
    @RegisterExtension
    protected static final CrossBrowserStorageExtension crossBrowserStorageExtension =
            new CrossBrowserStorageExtension();

    @Test
    void shouldStoreAndGetCrossBrowserItem() {
        crossBrowserStorageExtension.store(STATE, CLIENT_SESSION_ID);

        var actualClientSessionId =
                crossBrowserStorageExtension.getClientSessionIdFromState(STATE).orElseThrow();
        assertEquals(CLIENT_SESSION_ID, actualClientSessionId);
    }
}
