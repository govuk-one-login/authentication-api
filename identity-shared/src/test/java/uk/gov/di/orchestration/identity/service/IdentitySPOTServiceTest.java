package uk.gov.di.orchestration.identity.service;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.orchestration.audit.AuditContext;
import uk.gov.di.orchestration.identity.entity.IdentityProcessingEndState;
import uk.gov.di.orchestration.identity.entity.LogIds;
import uk.gov.di.orchestration.identity.entity.SPOTRequest;
import uk.gov.di.orchestration.shared.api.AuthFrontend;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.AwsSqsClient;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.identity.entity.SPOTAuditableEvent.IPV_SPOT_REQUESTED;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withMessageContaining;

public class IdentitySPOTServiceTest {
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AwsSqsClient spotSqsClient = mock(AwsSqsClient.class);
    private final OidcAPI oidcAPI = mock(OidcAPI.class);
    private final SerializationService objectMapper = spy(SerializationService.getInstance());
    private final IdentityProgressService identityProgressService =
            mock(IdentityProgressService.class);
    private final AuthFrontend frontend = mock(AuthFrontend.class);
    private final AuditService auditService = mock(AuditService.class);
    private static final URI OIDC_TRUSTMARK_URI = URI.create("https://base-url.com/trustmark");
    private static final UserInfo P2_VOT_USER_IDENTITY_USER_INFO =
            new UserInfo(
                    new JSONObject(
                            Map.of(
                                    "sub", "sub-val",
                                    "vot", "P2",
                                    "vtm", OIDC_TRUSTMARK_URI.toString(),
                                    "https://vocab.account.gov.uk/v1/coreIdentity", "core-identity",
                                    "https://vocab.account.gov.uk/v1/passport", "passport")));
    private static final Subject SUBJECT = new Subject("subject-id");
    private static final ClientID CLIENT_ID = new ClientID();
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final String TEST_EMAIL_ADDRESS = "test@test.com";
    private static final String TEST_PHONE_NUMBER = "012345678902";
    private static final String TEST_INTERNAL_COMMON_SUBJECT_ID = "internal-common-subject-id";
    private static final byte[] salt =
            "Mmc48imEuO5kkVW7NtXVtx5h0mbCTfXsqXdWvbRMzdw=".getBytes(StandardCharsets.UTF_8);
    private static final String BASE_64_ENCODED_SALT = Base64.getEncoder().encodeToString(salt);
    private static final UserInfo AUTH_USER_INFO = generateAuthUserInfo();
    private static final AuditContext AUDIT_CONTEXT = mock(AuditContext.class);
    private static final String FRONTEND_IPV_CALLBACK_URI = "http://frontend/ipv";
    private static final String FRONTEND_ERROR_URI = "http://frontend/error";

    private IdentitySPOTService service;

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(IdentitySPOTService.class);

    @BeforeEach
    void setup() throws Exception {
        // TODO: We might be able to get rid of this flag?
        when(configurationService.isNewSpotRequestQueueWritingEnabled()).thenReturn(true);
        when(frontend.ipvCallbackURI()).thenReturn(new URI(FRONTEND_IPV_CALLBACK_URI));
        when(frontend.errorURI()).thenReturn(new URI(FRONTEND_ERROR_URI));
        service =
                new IdentitySPOTService(
                        configurationService,
                        spotSqsClient,
                        oidcAPI,
                        objectMapper,
                        identityProgressService,
                        frontend,
                        auditService);
    }

    @Nested
    class QueueSpotRequest {
        @Test
        void shouldQueueSPOTRequestIfValidFormat() {
            when(oidcAPI.trustmarkURI()).thenReturn(OIDC_TRUSTMARK_URI);
            service.queueSPOTRequest(
                    new LogIds(),
                    "sector-identifier",
                    AUTH_USER_INFO,
                    SUBJECT,
                    P2_VOT_USER_IDENTITY_USER_INFO,
                    CLIENT_ID.getValue(),
                    AUDIT_CONTEXT);

            assertThat(
                    logging.events(),
                    hasItem(withMessageContaining("Constructing SPOT request ready to queue")));
            var spotRequestString =
                    "{\"in_claims\":{\"https://vocab.account.gov.uk/v1/coreIdentity\":\"core-identity\",\"https://vocab.account.gov.uk/v1/credentialJWT\":null,\"vot\":\"P2\",\"vtm\":\"https://base-url.com/trustmark\"},\"in_local_account_id\":\"subject-id\","
                            + "\"in_salt\":"
                            + objectMapper.writeValueAsString(BASE_64_ENCODED_SALT)
                            + ",\"in_rp_sector_id\":\"sector-identifier\",\"out_sub\":\"subject-id\",\"log_ids\":{\"session_id\":null,\"persistent_session_id\":null,\"request_id\":null,\"client_id\":null,\"client_session_id\":null},\"out_audience\":\""
                            + CLIENT_ID.getValue()
                            + "\"}";
            verify(spotSqsClient).send(spotRequestString);
            assertThat(
                    logging.events(),
                    hasItem(withMessageContaining("SPOT request placed on queue")));
            verify(auditService).submitAuditEvent(IPV_SPOT_REQUESTED, AUDIT_CONTEXT);
        }

        @Test
        void shouldThrowJsonExceptionAndDoesNotInteractWithSqsIfCannotMapRequestToJson() {
            when(oidcAPI.trustmarkURI()).thenReturn(OIDC_TRUSTMARK_URI);
            when(objectMapper.writeValueAsString(any(SPOTRequest.class)))
                    .thenThrow(new Json.JsonException("json-exception"));

            var exception =
                    assertThrows(
                            Json.JsonException.class,
                            () ->
                                    service.queueSPOTRequest(
                                            new LogIds(),
                                            "sector-identifier",
                                            AUTH_USER_INFO,
                                            SUBJECT,
                                            P2_VOT_USER_IDENTITY_USER_INFO,
                                            CLIENT_ID.getValue(),
                                            AUDIT_CONTEXT),
                            "Expected to throw JsonException");

            assertThat(
                    logging.events(),
                    hasItem(withMessageContaining("Constructing SPOT request ready to queue")));
            verifyNoInteractions(spotSqsClient);
            verifyNoInteractions(auditService);
            assertEquals("json-exception", exception.getMessage());
        }
    }

    @Nested
    class WaitForSPOT {

        @Test
        void shouldRedirectToFrontendWhenSyncWaitForSPOTDisabled() throws Exception {
            when(configurationService.isSyncWaitForSpotEnabled()).thenReturn(false);

            var redirectOpt = service.waitForSpot(CLIENT_SESSION_ID, AUDIT_CONTEXT);

            assertTrue(redirectOpt.isPresent());
            var redirect = redirectOpt.get();
            assertThat(
                    redirect.getHeaders().get("Location"), startsWith(FRONTEND_IPV_CALLBACK_URI));
        }

        @Test
        void shouldRedirectToFrontendErrorPageWhenSyncWaitForSPOTReturnsError() throws Exception {
            when(configurationService.isSyncWaitForSpotEnabled()).thenReturn(true);
            when(identityProgressService.pollForStatus(CLIENT_SESSION_ID, AUDIT_CONTEXT))
                    .thenReturn(IdentityProcessingEndState.ERROR);

            var redirectOpt = service.waitForSpot(CLIENT_SESSION_ID, AUDIT_CONTEXT);

            assertTrue(redirectOpt.isPresent());
            var redirect = redirectOpt.get();
            assertThat(redirect.getHeaders().get("Location"), startsWith(FRONTEND_ERROR_URI));
        }

        @Test
        void shouldRedirectToFrontendErrorPageWhenSyncWaitForSPOTReturnsNoEntry() throws Exception {
            when(configurationService.isSyncWaitForSpotEnabled()).thenReturn(true);
            when(identityProgressService.pollForStatus(CLIENT_SESSION_ID, AUDIT_CONTEXT))
                    .thenReturn(IdentityProcessingEndState.NO_ENTRY);

            var redirectOpt = service.waitForSpot(CLIENT_SESSION_ID, AUDIT_CONTEXT);

            assertTrue(redirectOpt.isPresent());
            var redirect = redirectOpt.get();
            assertThat(redirect.getHeaders().get("Location"), startsWith(FRONTEND_ERROR_URI));
        }

        @Test
        void shouldNotRedirectYetWhenSyncWaitForSPOTReturnsCompleted() throws Exception {
            when(configurationService.isSyncWaitForSpotEnabled()).thenReturn(true);
            when(identityProgressService.pollForStatus(CLIENT_SESSION_ID, AUDIT_CONTEXT))
                    .thenReturn(IdentityProcessingEndState.COMPLETED);

            var redirectOpt = service.waitForSpot(CLIENT_SESSION_ID, AUDIT_CONTEXT);

            assertTrue(redirectOpt.isEmpty());
        }
    }

    private static UserInfo generateAuthUserInfo() {
        return new UserInfo(
                new JSONObject(
                        Map.of(
                                "sub",
                                TEST_INTERNAL_COMMON_SUBJECT_ID,
                                "client_session_id",
                                CLIENT_SESSION_ID,
                                "email",
                                TEST_EMAIL_ADDRESS,
                                "phone_number",
                                TEST_PHONE_NUMBER,
                                "salt",
                                BASE_64_ENCODED_SALT,
                                "local_account_id",
                                SUBJECT.getValue())));
    }
}
