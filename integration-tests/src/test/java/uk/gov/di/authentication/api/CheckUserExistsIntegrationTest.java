package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.id.ClientID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import uk.gov.di.authentication.frontendapi.entity.CheckUserExistsRequest;
import uk.gov.di.authentication.frontendapi.entity.CheckUserExistsResponse;
import uk.gov.di.authentication.frontendapi.lambda.CheckUserExistsHandler;
import uk.gov.di.authentication.shared.entity.BaseFrontendRequest;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_ACCOUNT_TEMPORARILY_LOCKED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_CHECK_USER_KNOWN_EMAIL;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_CHECK_USER_NO_ACCOUNT_WITH_EMAIL;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class CheckUserExistsIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final URI REDIRECT_URI =
            URI.create(System.getenv("STUB_RELYING_PARTY_REDIRECT_URI"));
    private static final ClientID CLIENT_ID = new ClientID("test-client");
    private static final String CLIENT_NAME = "some-client-name";

    @BeforeEach
    void setup() {
        handler =
                new CheckUserExistsHandler(
                        TXMA_ENABLED_CONFIGURATION_SERVICE, redisConnectionService);
        txmaAuditQueue.clear();
    }

    @ParameterizedTest
    @EnumSource(
            value = MFAMethodType.class,
            names = {"SMS", "AUTH_APP"})
    void shouldCallUserExistsEndpointAndReturnAuthenticationRequestStateWhenUserExists(
            MFAMethodType mfaMethodType) throws JsonException, URISyntaxException {
        var emailAddress = "joe.bloggs+1@digital.cabinet-office.gov.uk";
        var sessionId = IdGenerator.generate();
        authSessionStore.addSession(sessionId);
        authSessionStore.addClientIdToSession(sessionId, CLIENT_ID.getValue());
        var clientSessionId = IdGenerator.generate();
        userStore.signUp(emailAddress, "password-1");
        var salt = userStore.addSalt(emailAddress);

        var userProfile = userStore.getUserProfileFromEmail(emailAddress).orElseThrow();
        var expectedInternalCommonSubjectId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        userProfile.getSubjectID(),
                        new URI(TXMA_ENABLED_CONFIGURATION_SERVICE.getInternalSectorUri()),
                        salt);

        if (MFAMethodType.SMS == mfaMethodType) {
            userStore.addMfaMethod(emailAddress, mfaMethodType, false, true, "credential");
            userStore.addVerifiedPhoneNumber(emailAddress, "+44987654321");
        } else {
            userStore.addMfaMethod(emailAddress, mfaMethodType, true, true, "credential");
        }

        registerClient(
                "joe.bloggs+1@digital.cabinet-office.gov.uk", CLIENT_ID, CLIENT_NAME, REDIRECT_URI);

        var request = new CheckUserExistsRequest(emailAddress);
        var response =
                makeRequest(
                        Optional.of(request),
                        constructFrontendHeaders(sessionId, clientSessionId),
                        Map.of());

        assertThat(response, hasStatus(200));
        CheckUserExistsResponse checkUserExistsResponse =
                objectMapper.readValue(response.getBody(), CheckUserExistsResponse.class);
        assertThat(checkUserExistsResponse.email(), equalTo(emailAddress));
        assertThat(checkUserExistsResponse.mfaMethodType(), equalTo(mfaMethodType));
        assertTrue(checkUserExistsResponse.doesUserExist());
        assertThat(
                authSessionStore.getSession(sessionId).orElseThrow().getInternalCommonSubjectId(),
                equalTo(expectedInternalCommonSubjectId));
        if (MFAMethodType.SMS.equals(mfaMethodType)) {
            assertThat(checkUserExistsResponse.phoneNumberLastThree(), equalTo("321"));
        } else if (MFAMethodType.AUTH_APP.equals(mfaMethodType)) {
            assertNull(checkUserExistsResponse.phoneNumberLastThree());
        }
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_CHECK_USER_KNOWN_EMAIL));
    }

    @Test
    void shouldCallUserExistsEndpointAndReturnLockoutInformationForAuthAppMfa()
            throws JsonException {
        var emailAddress = "joe.bloggs+1@digital.cabinet-office.gov.uk";

        String sessionId = IdGenerator.generate();
        authSessionStore.addSession(sessionId);
        authSessionStore.addClientIdToSession(sessionId, CLIENT_ID.getValue());
        var codeRequestType =
                CodeRequestType.getCodeRequestType(MFAMethodType.AUTH_APP, JourneyType.SIGN_IN);

        userStore.signUp(emailAddress, "password-1");
        userStore.addMfaMethod(emailAddress, MFAMethodType.AUTH_APP, true, true, "credential");

        var clientSessionId = IdGenerator.generate();

        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;
        redis.blockMfaCodesForEmail(emailAddress, codeBlockedKeyPrefix);

        registerClient(
                "joe.bloggs+1@digital.cabinet-office.gov.uk", CLIENT_ID, CLIENT_NAME, REDIRECT_URI);

        var request = new CheckUserExistsRequest(emailAddress);
        var response =
                makeRequest(
                        Optional.of(request),
                        constructFrontendHeaders(sessionId, clientSessionId),
                        Map.of());

        assertThat(response, hasStatus(200));
        CheckUserExistsResponse checkUserExistsResponse =
                objectMapper.readValue(response.getBody(), CheckUserExistsResponse.class);
        assertThat(checkUserExistsResponse.email(), equalTo(emailAddress));
        assertThat(checkUserExistsResponse.mfaMethodType(), equalTo(MFAMethodType.AUTH_APP));
        assertTrue(checkUserExistsResponse.doesUserExist());
        var lockoutInformation = checkUserExistsResponse.lockoutInformation();
        assertNotNull(lockoutInformation);
        assertThat(lockoutInformation.get(0).lockTTL() > 0, is(true));
        assertThat(lockoutInformation.get(0).journeyType(), is(JourneyType.SIGN_IN));
        assertThat(lockoutInformation.get(0).mfaMethodType(), is(MFAMethodType.AUTH_APP));

        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_CHECK_USER_KNOWN_EMAIL));
    }

    @Test
    void shouldCallUserExistsEndpointAndReturnUserNotFoundStateWhenUserDoesNotExist()
            throws JsonException {
        String emailAddress = "joe.bloggs+2@digital.cabinet-office.gov.uk";
        String sessionId = IdGenerator.generate();
        authSessionStore.addSession(sessionId);
        var clientSessionId = IdGenerator.generate();
        registerClient(emailAddress, CLIENT_ID, CLIENT_NAME, REDIRECT_URI);
        BaseFrontendRequest request = new CheckUserExistsRequest(emailAddress);

        var response =
                makeRequest(
                        Optional.of(request),
                        constructFrontendHeaders(sessionId, clientSessionId),
                        Map.of());

        assertThat(response, hasStatus(200));

        CheckUserExistsResponse checkUserExistsResponse =
                objectMapper.readValue(response.getBody(), CheckUserExistsResponse.class);
        assertThat(checkUserExistsResponse.email(), equalTo(emailAddress));
        assertThat(checkUserExistsResponse.mfaMethodType(), equalTo(MFAMethodType.NONE));
        assertFalse(checkUserExistsResponse.doesUserExist());
        assertNull(checkUserExistsResponse.phoneNumberLastThree());
        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(AUTH_CHECK_USER_NO_ACCOUNT_WITH_EMAIL));
    }

    @Test
    void shouldCallUserExistsEndpointAndReturnErrorResponse1045WhenUserAccountIsLocked()
            throws JsonException {
        String emailAddress = "joe.bloggs+2@digital.cabinet-office.gov.uk";
        String sessionId = IdGenerator.generate();
        authSessionStore.addSession(sessionId);
        redis.blockMfaCodesForEmail(
                emailAddress,
                CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX + JourneyType.PASSWORD_RESET);

        BaseFrontendRequest request = new CheckUserExistsRequest(emailAddress);

        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("X-API-Key", FRONTEND_API_KEY);

        var response =
                makeRequest(
                        Optional.of(request),
                        constructFrontendHeaders(sessionId),
                        headers,
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1045));

        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_ACCOUNT_TEMPORARILY_LOCKED));
    }
}
