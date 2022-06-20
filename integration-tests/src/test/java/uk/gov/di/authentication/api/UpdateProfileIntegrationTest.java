package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.bouncycastle.util.encoders.Base32;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.frontendapi.entity.UpdateProfileRequest;
import uk.gov.di.authentication.frontendapi.lambda.UpdateProfileHandler;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.net.URI;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.UPDATE_PROFILE_REQUEST_RECEIVED;
import static uk.gov.di.authentication.frontendapi.entity.UpdateProfileType.ADD_PHONE_NUMBER;
import static uk.gov.di.authentication.frontendapi.entity.UpdateProfileType.CAPTURE_CONSENT;
import static uk.gov.di.authentication.frontendapi.entity.UpdateProfileType.REGISTER_AUTH_APP;
import static uk.gov.di.authentication.frontendapi.entity.UpdateProfileType.UPDATE_TERMS_CONDS;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertEventTypesReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class UpdateProfileIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String EMAIL_ADDRESS = "test@test.com";
    private static final String CLIENT_ID = "test-id";

    @BeforeEach
    void setup() {
        handler = new UpdateProfileHandler(TEST_CONFIGURATION_SERVICE);
    }

    private static Stream<String> phoneNumbers() {
        return Stream.of(
                "+447316763843",
                "+4407316763843",
                "+33645453322",
                "+447316763843",
                "+33645453322",
                "+33645453322",
                "07911123456",
                "07123456789");
    }

    @ParameterizedTest
    @MethodSource("phoneNumbers")
    void shouldCallUpdateProfileEndpointToUpdatePhoneNumberAndReturn204(String phonenumber)
            throws Json.JsonException {
        String sessionId = redis.createSession();
        String clientSessionId = IdGenerator.generate();
        setUpTest(sessionId, clientSessionId);
        UpdateProfileRequest request =
                new UpdateProfileRequest(EMAIL_ADDRESS, ADD_PHONE_NUMBER, phonenumber);

        var response =
                makeRequest(
                        Optional.of(request),
                        constructFrontendHeaders(sessionId, clientSessionId),
                        Map.of());

        assertThat(response, hasStatus(204));

        assertEventTypesReceived(
                auditTopic,
                List.of(UPDATE_PROFILE_REQUEST_RECEIVED, UPDATE_PROFILE_REQUEST_RECEIVED));
    }

    @Test
    void shouldCallUpdateProfileToUpdateConsentAndReturn204() throws Json.JsonException {
        String sessionId = redis.createSession();
        String clientSessionId = IdGenerator.generate();
        AuthenticationRequest authRequest = setUpTest(sessionId, clientSessionId);
        redis.createClientSession(clientSessionId, authRequest.toParameters());
        UpdateProfileRequest request =
                new UpdateProfileRequest(EMAIL_ADDRESS, CAPTURE_CONSENT, String.valueOf(true));

        var response =
                makeRequest(
                        Optional.of(request),
                        constructFrontendHeaders(sessionId, clientSessionId),
                        Map.of());

        assertThat(response, hasStatus(204));
        Optional<ClientConsent> consent =
                userStore
                        .getUserConsents(EMAIL_ADDRESS)
                        .flatMap(
                                list ->
                                        list.stream()
                                                .filter(c -> c.getClientId().equals(CLIENT_ID))
                                                .findFirst());
        assertTrue(consent.get().getClaims().containsAll(OIDCScopeValue.OPENID.getClaimNames()));
        assertTrue(consent.get().getClaims().containsAll(OIDCScopeValue.EMAIL.getClaimNames()));

        assertEventTypesReceived(
                auditTopic,
                List.of(UPDATE_PROFILE_REQUEST_RECEIVED, UPDATE_PROFILE_REQUEST_RECEIVED));
    }

    @Test
    void shouldCallUpdateProfileToApproveTermsAndConditionsAndReturn204()
            throws Json.JsonException {
        String sessionId = redis.createSession();
        String clientSessionId = IdGenerator.generate();
        setUpTest(sessionId, clientSessionId);

        UpdateProfileRequest request =
                new UpdateProfileRequest(EMAIL_ADDRESS, UPDATE_TERMS_CONDS, String.valueOf(true));

        var response =
                makeRequest(
                        Optional.of(request),
                        constructFrontendHeaders(sessionId, clientSessionId),
                        Map.of());

        assertThat(response, hasStatus(204));
        assertEventTypesReceived(
                auditTopic,
                List.of(UPDATE_PROFILE_REQUEST_RECEIVED, UPDATE_PROFILE_REQUEST_RECEIVED));
    }

    @Test
    void shouldCallUpdateProfileToAddAuthAppAndReturn204() throws Json.JsonException {
        var sessionId = redis.createSession();
        var clientSessionId = IdGenerator.generate();
        setUpTest(sessionId, clientSessionId);
        var authAppSecret = Base32.toBase32String("some-secret".getBytes());

        var request = new UpdateProfileRequest(EMAIL_ADDRESS, REGISTER_AUTH_APP, authAppSecret);

        var response =
                makeRequest(
                        Optional.of(request),
                        constructFrontendHeaders(sessionId, clientSessionId),
                        Map.of());

        assertThat(response, hasStatus(204));
        var mfaMethod = userStore.getMfaMethod(EMAIL_ADDRESS);
        assertNotNull(mfaMethod);
        assertThat(mfaMethod.size(), equalTo(1));
        assertThat(mfaMethod.get(0).getCredentialValue(), equalTo(authAppSecret));
        assertThat(mfaMethod.get(0).isMethodVerified(), equalTo(false));
        assertThat(mfaMethod.get(0).isEnabled(), equalTo(true));
        assertEventTypesReceived(
                auditTopic,
                List.of(UPDATE_PROFILE_REQUEST_RECEIVED, UPDATE_PROFILE_REQUEST_RECEIVED));
    }

    private AuthenticationRequest setUpTest(String sessionId, String clientSessionId)
            throws Json.JsonException {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        scope.add(OIDCScopeValue.EMAIL);
        redis.addEmailToSession(sessionId, EMAIL_ADDRESS);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                scope,
                                new ClientID(CLIENT_ID),
                                URI.create("http://localhost/redirect"))
                        .nonce(new Nonce())
                        .build();
        redis.createClientSession(clientSessionId, authRequest.toParameters());
        clientStore.registerClient(
                CLIENT_ID,
                "test-client",
                singletonList("redirect-url"),
                singletonList(EMAIL_ADDRESS),
                List.of("openid", "email"),
                "public-key",
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public",
                true);
        Set<String> claims = ValidScopes.getClaimsForListOfScopes(scope.toStringList());
        userStore.signUp(EMAIL_ADDRESS, "password");
        userStore.updateConsent(
                EMAIL_ADDRESS,
                new ClientConsent(
                        CLIENT_ID, claims, LocalDateTime.now(ZoneId.of("UTC")).toString()));
        return authRequest;
    }
}
