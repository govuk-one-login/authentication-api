package uk.gov.di.authentication.clientregistry;

import org.junit.jupiter.api.Test;

import static uk.gov.di.orchestration.sharedtest.helper.DynatraceHelper.assertHandlersHaveOwnHandleRequestMethods;

public class DynatraceTest {
    @Test
    void allHandlersHaveOwnHandleRequestMethod() {
        assertHandlersHaveOwnHandleRequestMethods("uk.gov.di.authentication.clientregistry.lambda");
    }
}
