package uk.gov.di.accountmanagement.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.accountmanagement.lambda.MFAMethodsRetrieveHandler;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.UserStoreExtension;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class MfaMethodsRetrieveHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String EMAIL = "joe.bloggs+3@digital.cabinet-office.gov.uk";
    private static final String PASSWORD = "password-1";

    @RegisterExtension
    private static UserStoreExtension userStoreExtension = new UserStoreExtension();

    @BeforeEach
    void setUp() {
        handler = new MFAMethodsRetrieveHandler(TEST_CONFIGURATION_SERVICE);
    }

    @Test
    void shouldReturn200WhenUserExists() {
        var publicSubjectId = userStoreExtension.signUp(EMAIL, PASSWORD);

        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", publicSubjectId),
                        Collections.emptyMap());

        assertEquals(200, response.getStatusCode());
        assertEquals("{\"hello\": \"world\"}", response.getBody());
    }

    @Test
    void shouldReturn404WhenUserDoesNotExist() {
        var publicSubjectId = "userDoesNotExist";
        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", publicSubjectId),
                        Collections.emptyMap());

        assertEquals(404, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1056));
    }
}
