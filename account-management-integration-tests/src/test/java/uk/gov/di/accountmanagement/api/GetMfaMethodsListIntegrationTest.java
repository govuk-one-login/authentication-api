package uk.gov.di.accountmanagement.api;

import com.nimbusds.jose.JOSEException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.GetMfaMethodsRequest;
import uk.gov.di.accountmanagement.lambda.GetMfaMethodsHandler;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class GetMfaMethodsListIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String USER_EMAIL = "test@email.com";

    private static final String USER_PASSWORD = "Password123!";

    private String SESSION_ID;

    @BeforeEach
    void setup() throws JOSEException, NoSuchAlgorithmException, Json.JsonException {
        var configuration =
                new IntegrationTestConfigurationService(
                        auditTopic,
                        notificationsQueue,
                        auditSigningKey,
                        tokenSigner,
                        ipvPrivateKeyJwtSigner,
                        spotQueue,
                        docAppPrivateKeyJwtSigner,
                        configurationParameters) {

                    @Override
                    public String getTxmaAuditQueueUrl() {
                        return txmaAuditQueue.getQueueUrl();
                    }
                };
        String subjectId = "new-subject";
        SESSION_ID = redis.createUnauthenticatedSessionWithEmail(USER_EMAIL);

        handler = new GetMfaMethodsHandler();
    }

    @Test
    void shouldCallMFAInforAndReturn200() throws Json.JsonException, ParseException {
        var response =
                makeRequest(
                        Optional.of(new GetMfaMethodsRequest(USER_EMAIL)),
                        constructFrontendHeaders(SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(200));
    }
}
