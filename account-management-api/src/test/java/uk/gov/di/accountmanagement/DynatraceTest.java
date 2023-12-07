package uk.gov.di.accountmanagement;

import org.junit.jupiter.api.Test;

import static uk.gov.di.authentication.sharedtest.helper.DynatraceHelper.assertHandlersHaveOwnHandleRequestMethods;

public class DynatraceTest {
    @Test
    void allHandlersHaveOwnHandleRequestMethod() {
        assertHandlersHaveOwnHandleRequestMethods("uk.gov.di.accountmanagement.lambda");
    }
}
