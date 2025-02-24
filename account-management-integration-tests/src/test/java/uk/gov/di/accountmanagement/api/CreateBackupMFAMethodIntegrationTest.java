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
                        Optional.of(
                                "{\n"
                                        + "\"mfaMethod\": {\n"
                                        + "\"priorityIdentifier\": \"BACKUP\",\n"
                                        + "\"method\": {\n"
                                        + "\"mfaMethodType\": \"AUTH_APP\",\n"
                                        + "\"credential\": \"AAAABBBBCCCCCDDDDD55551111EEEE2222FFFF3333GGGG4444\"\n"
                                        + "}\n"
                                        + "}\n"
                                        + "}"),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", "helloPath"),
                        Collections.emptyMap());

        assertEquals(200, response.getStatusCode());
        assertEquals(
                "{\n"
                        + "\"mfaMethod\": {\n"
                        + "\"priorityIdentifier\": \"BACKUP\",\n"
                        + "\"method\": {\n"
                        + "\"mfaMethodType\": \"AUTH_APP\",\n"
                        + "\"credential\": \"AAAABBBBCCCCCDDDDD55551111EEEE2222FFFF3333GGGG4444\"\n"
                        + "}\n"
                        + "}\n"
                        + "}",
                response.getBody());
    }

    @Test
    void shouldReturn400AndBadRequestWhenPathParameterIsWrong() {
        var response =
                makeRequest(
                        Optional.of(
                                "{\n"
                                        + "\"mfaMethod\": {\n"
                                        + "\"priorityIdentifier\": \"BACKUP\",\n"
                                        + "\"method\": {\n"
                                        + "\"mfaMethodType\": \"AUTH_APP\",\n"
                                        + "\"credential\": \"AAAABBBBCCCCCDDDDD55551111EEEE2222FFFF3333GGGG4444\"\n"
                                        + "}\n"
                                        + "}\n"
                                        + "}"),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", "wrongPath"),
                        Collections.emptyMap());

        assertEquals(400, response.getStatusCode());
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1001));
    }
}
