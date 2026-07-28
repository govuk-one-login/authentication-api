package uk.gov.di.accountdata.lambda;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountdata.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.accountdata.lambda.AccountDeleteHandler;
import uk.gov.di.authentication.accountdata.services.ConfigurationService;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;

class AccountDeleteHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String PUBLIC_SUBJECT_ID_KEY = "publicSubjectId";
    private static final String TEST_EMAIL = "account-delete-test@example.com";
    private static final String TEST_PASSWORD = "password-1";
    private static final Subject TEST_SUBJECT = new Subject();

    private final ConfigurationService configurationService = new ConfigurationService();
    private final DynamoService dynamoService = new DynamoService(configurationService);

    @BeforeEach
    void setUp() {
        handler = new AccountDeleteHandler(configurationService, dynamoService);
    }

    @Test
    void shouldReturn204WhenUserExists() {
        var user =
                dynamoService.signUp(
                        TEST_EMAIL,
                        TEST_PASSWORD,
                        TEST_SUBJECT,
                        new TermsAndConditions("1.0", "2024-01-01T00:00:00.000Z"));
        var publicSubjectId = user.getUserProfile().getPublicSubjectID();

        var result =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of(PUBLIC_SUBJECT_ID_KEY, publicSubjectId),
                        Collections.emptyMap());

        assertThat(result.getStatusCode(), equalTo(204));
    }

    @Test
    void shouldReturn404WhenUserDoesNotExist() {
        var result =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of(PUBLIC_SUBJECT_ID_KEY, "non-existent-subject-id"),
                        Collections.emptyMap());

        assertEquals(
                "{\"code\":1056,\"message\":\"User not found or no match\"}", result.getBody());
        assertThat(result.getStatusCode(), equalTo(404));
    }

    @Test
    void shouldReturn400WhenPublicSubjectIdMissing() {
        var result =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Collections.emptyMap());

        assertEquals(
                "{\"code\":1001,\"message\":\"Request is missing parameters\"}", result.getBody());
        assertThat(result.getStatusCode(), equalTo(400));
    }

    @Test
    void shouldReturn400WhenPublicSubjectIdEmpty() {
        var result =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of(PUBLIC_SUBJECT_ID_KEY, ""),
                        Collections.emptyMap());

        assertEquals(
                "{\"code\":1001,\"message\":\"Request is missing parameters\"}", result.getBody());
        assertThat(result.getStatusCode(), equalTo(400));
    }
}
