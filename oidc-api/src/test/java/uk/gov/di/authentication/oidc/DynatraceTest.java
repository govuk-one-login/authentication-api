package uk.gov.di.authentication.oidc;

import org.junit.jupiter.api.Test;

import static uk.gov.di.orchestration.sharedtest.helper.DynatraceHelper.assertHandlersHaveOwnHandleRequestMethods;

class DynatraceTest {
    @Test
    void allHandlersHaveOwnHandleRequestMethod() {
        assertHandlersHaveOwnHandleRequestMethods("uk.gov.di.authentication.oidc.lambda");
    }
}
