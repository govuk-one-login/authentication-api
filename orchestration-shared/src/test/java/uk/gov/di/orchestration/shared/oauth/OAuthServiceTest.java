package uk.gov.di.orchestration.shared.oauth;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequestSender;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ReadOnlyHTTPRequest;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import uk.gov.di.orchestration.shared.entity.OAuthConfiguration;
import uk.gov.di.orchestration.shared.entity.StateItem;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.CrossBrowserOrchestrationService;
import uk.gov.di.orchestration.shared.services.OrchJwtService;
import uk.gov.di.orchestration.shared.services.StateStorageService;
import uk.gov.di.orchestration.sharedtest.helper.Constants;

import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static com.nimbusds.common.contenttype.ContentType.APPLICATION_JSON;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class OAuthServiceTest {
    private static final NowHelper.NowClock fixedNowClock =
            new NowHelper.NowClock(Constants.FIXED_CLOCK);
    private static final OAuthConfiguration TEST_OAUTH_CONFIG =
            new OAuthConfiguration(
                    Constants.TEST_CLIENT_ID,
                    Constants.TEST_AUTHORIZE_URI,
                    Constants.TEST_TOKEN_URI,
                    Constants.TEST_USERINFO_URI,
                    Constants.TEST_CALLBACK_URI,
                    Constants.TEST_SIGNING_KEY_ALIAS,
                    Constants.TEST_PRIVATE_KEY_JWT_AUDIENCE);

    private final OrchJwtService jwtService = mock(OrchJwtService.class);
    private final StateStorageService stateStorageService = mock(StateStorageService.class);
    private final CrossBrowserOrchestrationService crossBrowserOrchestrationService =
            mock(CrossBrowserOrchestrationService.class);
    private final HTTPRequestSender mockHttpService = mock(HTTPRequestSender.class);
    private final RSAPublicKey publicKey = mock(RSAPublicKey.class);
    CallbackValidator noOpCallbackValidator =
            (queryParams, sessionId) -> BaseCallbackValidationError.INVALID_STATE;
    private OAuthService oAuthService;

    @BeforeEach
    void setup() {
        oAuthService =
                new OAuthService(
                        TEST_OAUTH_CONFIG,
                        jwtService,
                        fixedNowClock,
                        mockHttpService,
                        stateStorageService,
                        crossBrowserOrchestrationService,
                        noOpCallbackValidator);
    }

    @Nested
    class TokenRequestTests {
        private static final String MOCK_SERIALIZED_SIGNED_JWT =
                "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2MjY2ODQ1ODQsImlzcyI6Im15IGNsaWVudCBpZCIsInN1YiI6Im15IGNsaWVudCBpZCIsImF1ZCI6Imh0dHBzOi8vbXl0ZW5hbnQuYXV0aDAuY29tLyIsImV4cCI6MTYyNjY4NDY0NCwianRpIjoiZTRkYzhlZDEtYjEwOC00OTAxLThiYmMtYzA3YTc5MTgxN2U3In0.TSn6qTq2ioriY85GtPiC-a1ZvXSX5hmPRQ36DG3KV8e4-lWgTYru24yqBdg960pyAHp3OtNYzEaO_38eu7n9OK8c3biE1A5342PbSsLNS6IuI1MQTwM9nSS-u9RGehakKCYDpgUrjQloFcP-x3i944nAFOb708x_aa54L6SsLkL_gg565T0DWa56jFY35PSvybTIaPOq0LAquLrSlhOeClBCFOwx6HfAfgaDtbgbhtLAFDwdXXEUgSvhEUpIeSmN6FOcTXiyqZhTb70C2vM6JfICm-CEneUdMe8TpSo7QdDGhVKXjf-WJwUnkzjpgvkzU3MfYJOQIbiT-g4ytAOfqg";

        @Test
        void shouldCallTokenEndpointAndReturnWhenSuccessful()
                throws IOException, com.nimbusds.oauth2.sdk.ParseException {
            mockSigningJwt();
            var expectedTokenResponse = getSuccessfulTokenHttpResponse();
            when(mockHttpService.send(any(ReadOnlyHTTPRequest.class)))
                    .thenReturn(expectedTokenResponse);

            var tokenResponse = oAuthService.getToken(Constants.AUTHORIZATION_CODE.toString());

            assertThat(tokenResponse.indicatesSuccess(), equalTo(true));
            assertEquals(
                    expectedTokenResponse.getBodyAsJSONObject(),
                    tokenResponse.toHTTPResponse().getBodyAsJSONObject());
        }

        @Test
        void shouldRetryWithNewTokenRequestIfInitialRequestFails()
                throws IOException, com.nimbusds.oauth2.sdk.ParseException {
            mockSigningJwt();
            var expectedTokenResponse = getSuccessfulTokenHttpResponse();
            when(mockHttpService.send(any(ReadOnlyHTTPRequest.class)))
                    .thenReturn(failedTokenResponse())
                    .thenReturn(expectedTokenResponse);

            var tokenResponse = oAuthService.getToken(Constants.AUTHORIZATION_CODE.toString());

            assertThat(tokenResponse.indicatesSuccess(), equalTo(true));
            verify(mockHttpService, times(2)).send(any(ReadOnlyHTTPRequest.class));
            verify(jwtService, times(2))
                    .signJWT(any(JWTClaimsSet.class), eq(TEST_OAUTH_CONFIG.signingKeyAlias()));
            assertEquals(
                    expectedTokenResponse.getBodyAsJSONObject(),
                    tokenResponse.toHTTPResponse().getBodyAsJSONObject());
        }

        @Test
        void shouldReturnAFailureIfTwoCallsToTheTokenEndpointFail()
                throws IOException, com.nimbusds.oauth2.sdk.ParseException {
            mockSigningJwt();
            when(mockHttpService.send(any(ReadOnlyHTTPRequest.class)))
                    .thenReturn(failedTokenResponse())
                    .thenReturn(failedTokenResponse());

            var tokenResponse = oAuthService.getToken(Constants.AUTHORIZATION_CODE.toString());

            assertThat(tokenResponse.indicatesSuccess(), equalTo(false));
            verify(mockHttpService, times(2)).send(any(HTTPRequest.class));
            assertEquals(
                    failedTokenResponse().getBodyAsJSONObject(),
                    tokenResponse.toHTTPResponse().getBodyAsJSONObject());
        }

        @Test
        void eachTokenRequestShouldContainUniqueClientAssertionClaims() throws IOException {
            mockSigningJwt();
            when(mockHttpService.send(any(ReadOnlyHTTPRequest.class)))
                    .thenReturn(failedTokenResponse())
                    .thenReturn(getSuccessfulTokenHttpResponse());

            oAuthService.getToken(Constants.AUTHORIZATION_CODE.toString());

            var claimsSetArgumentCaptor = ArgumentCaptor.forClass(JWTClaimsSet.class);

            verify(mockHttpService, times(2)).send(any(HTTPRequest.class));
            verify(jwtService, times(2))
                    .signJWT(
                            claimsSetArgumentCaptor.capture(),
                            eq(TEST_OAUTH_CONFIG.signingKeyAlias()));

            var firstClaimSet = claimsSetArgumentCaptor.getAllValues().get(0);
            var secondClaimSet = claimsSetArgumentCaptor.getAllValues().get(1);
            assertNotEquals(firstClaimSet, secondClaimSet);
        }

        @Test
        void tokenRequestShouldContainPrivateKeyJwtClaims() throws IOException {
            mockSigningJwt();
            when(mockHttpService.send(any(ReadOnlyHTTPRequest.class)))
                    .thenReturn(getSuccessfulTokenHttpResponse());

            oAuthService.getToken(Constants.AUTHORIZATION_CODE.toString());

            var claimsSetArgumentCaptor = ArgumentCaptor.forClass(JWTClaimsSet.class);
            var expectedClaims =
                    new JWTClaimsSet.Builder()
                            // Our Client ID is provided as the issuer
                            .issuer(TEST_OAUTH_CONFIG.clientId())
                            .audience(TEST_OAUTH_CONFIG.privateKeyJwtAudience())
                            .expirationTime(fixedNowClock.nowPlus(5, ChronoUnit.MINUTES))
                            .issueTime(fixedNowClock.now())
                            .notBeforeTime(fixedNowClock.now())
                            .build();

            var verifier =
                    getFixedTimeJwtVerifier(
                            expectedClaims, Set.of("exp", "iat", "nbf", "jti", "iss"));
            verify(jwtService)
                    .signJWT(
                            claimsSetArgumentCaptor.capture(),
                            eq(TEST_OAUTH_CONFIG.signingKeyAlias()));

            var privateKeyJwtClaimsSet = claimsSetArgumentCaptor.getAllValues().get(0);

            assertDoesNotThrow(() -> verifier.verify(privateKeyJwtClaimsSet, null));
        }

        private void mockSigningJwt() {
            try {
                when(jwtService.signJWT(
                                any(JWTClaimsSet.class), eq(Constants.TEST_SIGNING_KEY_ALIAS)))
                        .thenReturn(SignedJWT.parse(MOCK_SERIALIZED_SIGNED_JWT));
            } catch (ParseException e) {
                throw new RuntimeException("Failed to parse JWT for test");
            }
        }

        private HTTPResponse getSuccessfulTokenHttpResponse() {
            var tokenResponseContent =
                    """
                    {
                        "access_token": "740e5834-3a29-46b4-9a6f-16142fde533a",
                        "token_type": "Bearer",
                        "expires_in": 3600
                    }
                    """;
            var tokenHTTPResponse = new HTTPResponse(200);
            tokenHTTPResponse.setEntityContentType(APPLICATION_JSON);
            tokenHTTPResponse.setBody(tokenResponseContent);

            return tokenHTTPResponse;
        }

        private HTTPResponse failedTokenResponse() {
            var tokenResponseContent =
                    """
                    {
                        "error": "invalid_grant",
                        "error_description": "Client authentication failed"
                    }
                    """;

            var tokenHTTPResponse = new HTTPResponse(401);
            tokenHTTPResponse.setEntityContentType(APPLICATION_JSON);
            tokenHTTPResponse.setBody(tokenResponseContent);
            return tokenHTTPResponse;
        }

        private DefaultJWTClaimsVerifier<SecurityContext> getFixedTimeJwtVerifier(
                JWTClaimsSet expectedJwtClaimSet, Set<String> mandatoryClaims) {
            return new DefaultJWTClaimsVerifier<>(expectedJwtClaimSet, mandatoryClaims) {
                @Override
                protected java.util.Date currentTime() {
                    // Add 5 seconds so current time is ahead of iat and nbf
                    return fixedNowClock.nowPlus(5, ChronoUnit.SECONDS);
                }
            };
        }
    }

    @Nested
    class UserinfoRequestTest {

        @Test
        void shouldCallUserInfoEndpointAndReturnWhenSuccessful()
                throws IOException,
                        UnsuccessfulCredentialResponseException,
                        com.nimbusds.oauth2.sdk.ParseException {
            when(mockHttpService.send(any(ReadOnlyHTTPRequest.class)))
                    .thenReturn(getSuccessfulUserinfoResponse());

            var userInfoResponse = oAuthService.getUserInfo(getTokenResponse());

            assertEquals(
                    getSuccessfulUserinfoResponse().getBodyAsJSONObject(),
                    userInfoResponse.toJSONObject());
            verify(mockHttpService, times(1)).send(any(ReadOnlyHTTPRequest.class));
        }

        @Test
        void shouldRetryIfInitialUserInfoRequestFails()
                throws IOException,
                        UnsuccessfulCredentialResponseException,
                        com.nimbusds.oauth2.sdk.ParseException {
            when(mockHttpService.send(any(ReadOnlyHTTPRequest.class)))
                    .thenReturn(getFailedUserInfoResponse())
                    .thenReturn(getSuccessfulUserinfoResponse());

            var userInfoResponse = oAuthService.getUserInfo(getTokenResponse());

            assertEquals(
                    getSuccessfulUserinfoResponse().getBodyAsJSONObject(),
                    userInfoResponse.toJSONObject());
            verify(mockHttpService, times(2)).send(any(ReadOnlyHTTPRequest.class));
        }

        @Test
        void shouldThrowUnsuccessfulCredentialResponseExceptionIfTwoRequestsFail()
                throws IOException {
            when(mockHttpService.send(any(ReadOnlyHTTPRequest.class)))
                    .thenReturn(getFailedUserInfoResponse())
                    .thenReturn(getFailedUserInfoResponse());

            assertThrows(
                    UnsuccessfulCredentialResponseException.class,
                    () -> oAuthService.getUserInfo(getTokenResponse()));

            verify(mockHttpService, times(2)).send(any(ReadOnlyHTTPRequest.class));
        }

        private HTTPResponse getSuccessfulUserinfoResponse() {
            var userInfoResponse = new HTTPResponse(200);
            userInfoResponse.setEntityContentType(APPLICATION_JSON);
            userInfoResponse.setBody(
                    """
               {
                   "sub": "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
                   "vot": "P2",
                   "vtm": "https://oidc.example.com/trustmark",
                   "https://vocab.example.gov.uk/v1/credentialJWT": [
                       "<JWT-encoded VC 1>",
                       "<JWT-encoded VC 2>"
                   ],
                   "https://vocab.example.gov.uk/v1/coreIdentity": {
                       "name": [
                           {}
                       ],
                       "birthDate": [
                           {}
                       ]
                   },
                   "phone_number_verified": true,
                   "email_address_verified": true
               }
               """);
            return userInfoResponse;
        }

        private HTTPResponse getFailedUserInfoResponse() {
            var userInfoResponse = new HTTPResponse(401);
            userInfoResponse.setEntityContentType(APPLICATION_JSON);
            userInfoResponse.setBody(
                    """
                    {
                        "error": "invalid_token",
                        "error_description": "The access token expired or is invalid."
                    }
                    """);
            userInfoResponse.setHeader(
                    "WWW-Authenticate",
                    "error=\"invalid_token\", error_description=\"The access token expired or is invalid.\"");

            return userInfoResponse;
        }
    }

    private AccessTokenResponse getTokenResponse() {
        return new AccessTokenResponse(new Tokens(new BearerAccessToken(), null), null);
    }

    @Nested
    class AuthorisationRequest {
        private static final String TEST_SERIALIZED_JWE =
                "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ";

        @Test
        void shouldCreateAuthorisationRequestFromClaimsAndKeyInfo() throws ParseException {
            mockSigningAndEncryption();
            var claims = new JWTClaimsSet.Builder().claim("hello", "world").build();
            var authenticationRequest = oAuthService.createAuthorisationRequest(claims, publicKey);

            assertEquals(
                    TEST_OAUTH_CONFIG.clientId(), authenticationRequest.getClientID().toString());
            assertEquals(TEST_SERIALIZED_JWE, authenticationRequest.getRequestObject().serialize());
            assertEquals(
                    TEST_OAUTH_CONFIG.authorizationURI(), authenticationRequest.getEndpointURI());
            assertEquals(ResponseType.CODE, authenticationRequest.getResponseType());
        }

        private void mockSigningAndEncryption() throws ParseException {
            when(jwtService.signAndEncryptJWT(
                            any(JWTClaimsSet.class),
                            eq(TEST_OAUTH_CONFIG.signingKeyAlias()),
                            any(RSAPublicKey.class)))
                    .thenReturn(EncryptedJWT.parse(TEST_SERIALIZED_JWE));
        }
    }

    @Nested
    class StateStorage {
        public String statePrefix = "state::";

        @Test
        void shouldValidateStateInDynamoMatchesStateProvided() {
            mockStatePresent();
            assertTrue(
                    oAuthService.isStateValid(
                            statePrefix, Constants.SESSION_ID, Constants.STATE.getValue()));
        }

        @Test
        void shouldReturnFalseForMissingState() {
            mockStateMissing();
            assertFalse(
                    oAuthService.isStateValid(
                            statePrefix, Constants.SESSION_ID, Constants.STATE.getValue()));
        }

        @Test
        void shouldReturnFalseForMismatchState() {
            mockStateMismatch();
            assertFalse(
                    oAuthService.isStateValid(
                            statePrefix, Constants.SESSION_ID, Constants.STATE.getValue()));
        }

        @Test
        void shouldStoreStateAgainstSessionAndClientSessionID() {
            oAuthService.storeState(
                    statePrefix,
                    Constants.STATE,
                    Constants.SESSION_ID,
                    Constants.CLIENT_SESSION_ID);

            verify(stateStorageService, times(1))
                    .storeState(statePrefix + Constants.SESSION_ID, Constants.STATE.getValue());
            verify(crossBrowserOrchestrationService, times(1))
                    .storeClientSessionIdAgainstState(Constants.CLIENT_SESSION_ID, Constants.STATE);
        }

        private void mockStatePresent() {
            when(stateStorageService.getState(anyString()))
                    .thenReturn(
                            Optional.of(
                                    new StateItem(statePrefix + Constants.SESSION_ID)
                                            .withState(Constants.STATE.getValue())));
        }

        private void mockStateMissing() {
            when(stateStorageService.getState(anyString())).thenReturn(Optional.empty());
        }

        private void mockStateMismatch() {
            when(stateStorageService.getState(anyString()))
                    .thenReturn(
                            Optional.of(
                                    new StateItem(statePrefix + Constants.SESSION_ID)
                                            .withState(new State().getValue())));
        }
    }

    @Nested
    class CallbackValidation {
        @Test
        void itDelegatesCallbackValidationToTheProvidedValidator() {
            var params =
                    Map.of(
                            "state",
                            Constants.STATE.getValue(),
                            "code",
                            Constants.AUTHORIZATION_CODE.getValue());
            var response = oAuthService.validateCallback(params, Constants.SESSION_ID);
            assertEquals(BaseCallbackValidationError.INVALID_STATE, response);
        }
    }
}
