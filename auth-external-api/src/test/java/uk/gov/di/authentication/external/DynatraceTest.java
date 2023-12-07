package uk.gov.di.authentication.external;

import org.junit.jupiter.api.Test;

import static uk.gov.di.authentication.sharedtest.helper.DynatraceHelper.assertHandlersHaveOwnHandleRequestMethods;

public class DynatraceTest {
    @Test
    void allHandlersHaveOwnHandleRequestMethod() {
        assertHandlersHaveOwnHandleRequestMethods("uk.gov.di.authentication.external.lambda");
    }
}
