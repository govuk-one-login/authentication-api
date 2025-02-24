package uk.gov.di.accountmanagement.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.lambda.CreateBackupMFAMethod;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class CreateBackupMFAMethodIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    @BeforeEach
    void setUp() {
        handler = new CreateBackupMFAMethod(TEST_CONFIGURATION_SERVICE);
    }

    @Test
    void shouldReturn200AndHelloWorld() {
        var response =
                makeRequest(
                        Optional.of("{\"mfaMethod\": \"Hello World\"}"),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", "helloPath"),
                        Collections.emptyMap());

        assertEquals(200, response.getStatusCode());
        assertEquals("{\"mfaMethod\": \"Hello World\"}", response.getBody());
    }

    @Test
    void shouldReturn400AndBadRequestWhenPathParameterIsWrong() {
        var response =
                makeRequest(
                        Optional.of("{\"mfaMethod\": \"Hello World\"}"),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", "wrongPath"),
                        Collections.emptyMap());

        assertEquals(400, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1001));
    }
}
