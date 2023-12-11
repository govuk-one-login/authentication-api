package uk.gov.di.authentication.api;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.frontendapi.entity.AccountInterventionsRequest;
import uk.gov.di.authentication.frontendapi.entity.AccountInterventionsResponse;
import uk.gov.di.authentication.frontendapi.lambda.AccountInterventionsHandler;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AccountInterventionsStubExtension;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class AccountInterventionsHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    public static final String CLIENT_SESSION_ID = "some-client-session-id";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_PASSWORD = "password-1";
    private static final String INTERNAl_SECTOR_HOST = "test.account.gov.uk";
    private static final Subject SUBJECT = new Subject();

    @RegisterExtension
    public static final AccountInterventionsStubExtension accountInterventionsStubExtension =
            new AccountInterventionsStubExtension();

    protected static final ConfigurationService
            ACCOUNT_INTERVENTIONS_HANDLER_CONFIGURATION_SERVICE =
                    new AccountInterventionsTestConfigurationService(
                            accountInterventionsStubExtension);

    @BeforeEach
    void setup() throws JOSEException, Json.JsonException {
        handler =
                new AccountInterventionsHandler(
                        ACCOUNT_INTERVENTIONS_HANDLER_CONFIGURATION_SERVICE);
        accountInterventionsStubExtension.init(setupUserAndRetrieveUserId(), false, false);
        txmaAuditQueue.clear();
    }

    @Test
    void shouldReturnSuccessful200Response() throws Json.JsonException {
        var response =
                makeRequest(
                        Optional.of(new AccountInterventionsRequest(TEST_EMAIL_ADDRESS)),
                        getHeaders(),
                        Map.of());
        assertThat(response, hasStatus(200));
        var accountInterventionsResponse = new AccountInterventionsResponse(false, false, false);
        assertThat(
                response,
                hasBody(objectMapper.writeValueAsStringCamelCase(accountInterventionsResponse)));
        assertEquals(
                response.getBody(),
                "{\"passwordResetRequired\":false,\"blocked\":false,\"temporarilySuspended\":false}");
    }

    private Map<String, String> getHeaders() throws Json.JsonException {
        Map<String, String> headers = new HashMap<>();
        var sessionId = redis.createSession();
        redis.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        headers.put("Session-Id", sessionId);
        return headers;
    }

    private static class AccountInterventionsTestConfigurationService
            extends IntegrationTestConfigurationService {

        private final AccountInterventionsStubExtension accountInterventionsStubExtension;

        public AccountInterventionsTestConfigurationService(
                AccountInterventionsStubExtension accountInterventionsStubExtension) {
            super(
                    auditTopic,
                    notificationsQueue,
                    auditSigningKey,
                    tokenSigner,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters);
            this.accountInterventionsStubExtension = accountInterventionsStubExtension;
        }

        @Override
        public URI getAccountInterventionServiceURI() {
            try {
                return new URIBuilder()
                        .setHost("localhost")
                        .setPort(accountInterventionsStubExtension.getHttpPort())
                        .setScheme("http")
                        .build();
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private String setupUserAndRetrieveUserId() {
        userStore.signUp(TEST_EMAIL_ADDRESS, TEST_PASSWORD, SUBJECT);
        byte[] salt = userStore.addSalt(TEST_EMAIL_ADDRESS);
        return ClientSubjectHelper.calculatePairwiseIdentifier(
                SUBJECT.getValue(), INTERNAl_SECTOR_HOST, salt);
    }
}
