package uk.gov.di.authentication.frontendapi.services.passkeys;

import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import uk.gov.di.authentication.frontendapi.entity.passkeys.PasskeyRetrieveError;
import uk.gov.di.authentication.frontendapi.entity.passkeys.PasskeyUpdateError;
import uk.gov.di.authentication.shared.entity.AccountDataScope;
import uk.gov.di.authentication.shared.entity.JwtFailureReason;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.services.AccessTokenConstructorService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.PUBLIC_SUBJECT_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.SESSION_ID;

class PasskeysServiceTest {
    ConfigurationService configurationService = mock(ConfigurationService.class);
    HttpClient httpClient = mock(HttpClient.class);
    HttpResponse httpResponse = mock(HttpResponse.class);
    AccessTokenConstructorService accessTokenConstructorService =
            mock(AccessTokenConstructorService.class);

    PasskeysService passkeysService =
            new PasskeysService(configurationService, httpClient, accessTokenConstructorService);

    private static final String ACCOUNT_DATA_BASE_URI = "https://example.com";
    private static final String RETRIEVE_PASSKEYS_URL =
            "%s/accounts/%s/authenticators/passkeys"
                    .formatted(ACCOUNT_DATA_BASE_URI, PUBLIC_SUBJECT_ID);
    private static final String PASSKEY_IDENTIFIER = "some-passkey-id";
    private static final String UPDATE_PASSKEY_URL =
            "%s/accounts/%s/authenticators/passkeys/%s"
                    .formatted(ACCOUNT_DATA_BASE_URI, PUBLIC_SUBJECT_ID, PASSKEY_IDENTIFIER);
    private static final BearerAccessToken ADAPI_BEARER_ACCESS_TOKEN =
            new BearerAccessToken("adapi_bearer");
    private static final String AUTH_ISSUER_CLAIM = "https://signin.account.gov.uk/";
    private static final String AUTH_TO_ACCOUNT_DATA_AUDIENCE = "https://example.com/ADAPIAudience";
    private static final String AMC_CLIENT_ID = "amc-client-id";
    private static final String AUTH_TO_ACCOUNT_DATA_SIGNING_KEY =
            "auth-to-account-data-signing-key";

    @BeforeEach
    void beforeEach() {
        when(configurationService.getAccountDataURI()).thenReturn(ACCOUNT_DATA_BASE_URI);
        when(configurationService.getAuthToAccountDataApiAudience())
                .thenReturn(AUTH_TO_ACCOUNT_DATA_AUDIENCE);
        when(configurationService.getAuthIssuerClaim()).thenReturn(AUTH_ISSUER_CLAIM);
        when(configurationService.getAMCClientId()).thenReturn(AMC_CLIENT_ID);
        when(configurationService.getAuthToAccountDataSigningKey())
                .thenReturn(AUTH_TO_ACCOUNT_DATA_SIGNING_KEY);
        when(accessTokenConstructorService.createSignedAccessToken(
                        any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Result.success(ADAPI_BEARER_ACCESS_TOKEN));
    }

    @AfterEach
    void afterEach() {
        reset(httpClient, configurationService, httpResponse);
    }

    @Nested
    class HasActivePasskey {
        private static Stream<Arguments> successfulTestCases() {
            return Stream.of(
                    Arguments.of(List.of(aPasskeyWithId("123456")), true),
                    Arguments.of(List.of(aPasskeyWithId("123456"), aPasskeyWithId("456789")), true),
                    Arguments.of(List.of(), false));
        }

        @MethodSource("successfulTestCases")
        @ParameterizedTest
        void hasActivePasskeyShouldReturnTheExpectedResultForASuccessfulPasskeysResponse(
                List<String> returnedPasskeys, boolean expectedResult)
                throws IOException, InterruptedException {
            var responseBody = passkeyResponse(returnedPasskeys);
            stubApiResponseToReturn(RETRIEVE_PASSKEYS_URL, 200, responseBody);

            var result = passkeysService.hasActivePasskey(PUBLIC_SUBJECT_ID, SESSION_ID);

            assertTrue(result.isSuccess());

            var hasActivePasskey = result.getSuccess();
            assertEquals(expectedResult, hasActivePasskey);
        }

        @Test
        void hasActivePasskeyShouldReturnFailureWhenAccountDataApiReturnsANon200ResponseCode()
                throws IOException, InterruptedException {
            stubApiResponseToReturn(RETRIEVE_PASSKEYS_URL, 500, "");

            var result = passkeysService.hasActivePasskey(PUBLIC_SUBJECT_ID, SESSION_ID);

            assertTrue(result.isFailure());

            var failure = result.getFailure();
            assertEquals(PasskeyRetrieveError.ERROR_RESPONSE_FROM_PASSKEY_RETRIEVE, failure);
        }

        @ValueSource(strings = {"{ invalid json ", "{\"foo\": \"bar\"}"})
        @ParameterizedTest
        void
                hasActivePasskeyShouldReturnFailureWhenAccountDataApiResponseReturnsResponseThatCannotBeParsedAsPasskeysRetrieveResponse(
                        String invalidResponseBody) throws IOException, InterruptedException {
            stubApiResponseToReturn(RETRIEVE_PASSKEYS_URL, 200, invalidResponseBody);

            var result = passkeysService.hasActivePasskey(PUBLIC_SUBJECT_ID, SESSION_ID);

            assertTrue(result.isFailure());

            var failure = result.getFailure();
            assertEquals(
                    PasskeyRetrieveError.ERROR_PARSING_RESPONSE_FROM_PASSKEY_RETRIEVE, failure);
        }

        private static Stream<Arguments> exceptionsToExpectedErrors() {
            return Stream.of(
                    Arguments.of(new IOException("uh oh"), PasskeyRetrieveError.IO_EXCEPTION),
                    Arguments.of(
                            new InterruptedException("uh oh"),
                            PasskeyRetrieveError.INTERRUPTED_EXCEPTION));
        }

        @MethodSource("exceptionsToExpectedErrors")
        @ParameterizedTest
        void hasActivePasskeyShouldReturnFailureWhenAccountDataApiThrowsAnIOException(
                Exception e, PasskeyRetrieveError expectedError)
                throws IOException, InterruptedException {
            when(httpClient.send(
                            argThat(
                                    request ->
                                            request.uri()
                                                    .equals(URI.create(RETRIEVE_PASSKEYS_URL))),
                            any()))
                    .thenThrow(e);

            var result = passkeysService.hasActivePasskey(PUBLIC_SUBJECT_ID, SESSION_ID);

            assertTrue(result.isFailure());

            var failure = result.getFailure();
            assertEquals(expectedError, failure);
        }

        @Test
        void retrievePasskeysShouldReturnFailureIfErrorCreatingAccessToken() {
            when(accessTokenConstructorService.createSignedAccessToken(
                            any(), any(), any(), any(), any(), any(), any(), any(), any()))
                    .thenReturn(Result.failure(JwtFailureReason.SIGNING_ERROR));

            var result = passkeysService.hasActivePasskey(PUBLIC_SUBJECT_ID, SESSION_ID);

            assertTrue(result.isFailure());
            assertEquals(PasskeyRetrieveError.ERROR_CREATING_ACCESS_TOKEN, result.getFailure());
            verifyNoInteractions(httpClient);
        }
    }

    @Nested
    class RetrievePasskeys {
        @Test
        void retrievePasskeysShouldReturnFullResponseOnSuccess()
                throws IOException, InterruptedException {
            var responseBody = passkeyResponse(List.of(aPasskeyWithId("123456")));
            stubApiResponseToReturn(RETRIEVE_PASSKEYS_URL, 200, responseBody);

            var result = passkeysService.retrievePasskeys(PUBLIC_SUBJECT_ID, SESSION_ID);
            assertTrue(result.isSuccess());
            assertEquals(1, result.getSuccess().passkeys().size());
            assertEquals("123456", result.getSuccess().passkeys().get(0).passkeyId());
        }

        @Test
        void retrievePasskeyShouldCreateAnAccessTokenWithTheRelevantData()
                throws IOException, InterruptedException {
            stubApiResponseToReturn(RETRIEVE_PASSKEYS_URL, 200, passkeyResponse(List.of()));

            var result = passkeysService.retrievePasskeys(PUBLIC_SUBJECT_ID, SESSION_ID);

            assertTrue(result.isSuccess());

            verify(accessTokenConstructorService)
                    .createSignedAccessToken(
                            eq(PUBLIC_SUBJECT_ID),
                            eq(List.of(AccountDataScope.PASSKEY_RETRIEVE)),
                            eq(SESSION_ID),
                            any(),
                            any(),
                            eq(AUTH_TO_ACCOUNT_DATA_AUDIENCE),
                            eq(AUTH_ISSUER_CLAIM),
                            eq(AMC_CLIENT_ID),
                            eq(AUTH_TO_ACCOUNT_DATA_SIGNING_KEY));
        }

        @Test
        void retrievePasskeysShouldMakeACallWithAnAuthorizationHeader()
                throws IOException, InterruptedException {
            stubApiResponseToReturn(RETRIEVE_PASSKEYS_URL, 200, passkeyResponse(List.of()));

            var result = passkeysService.hasActivePasskey(PUBLIC_SUBJECT_ID, SESSION_ID);

            assertTrue(result.isSuccess());

            var expectedAuthorizationHeader =
                    Optional.of(ADAPI_BEARER_ACCESS_TOKEN.toAuthorizationHeader());
            verify(httpClient)
                    .send(
                            argThat(
                                    request ->
                                            request.headers()
                                                    .firstValue("Authorization")
                                                    .equals(expectedAuthorizationHeader)),
                            any());
        }

        @Test
        void shouldReturnFailureWhenApiReturnsNon200() throws IOException, InterruptedException {
            stubApiResponseToReturn(RETRIEVE_PASSKEYS_URL, 500, "");

            var result = passkeysService.retrievePasskeys(PUBLIC_SUBJECT_ID, SESSION_ID);
            assertTrue(result.isFailure());
            assertEquals(
                    PasskeyRetrieveError.ERROR_RESPONSE_FROM_PASSKEY_RETRIEVE, result.getFailure());
        }
    }

    @Nested
    class UpdatePasskey {
        private static final String FIXED_TIMESTAMP = "2021-09-01T22:10:00.012Z";
        private static final Clock FIXED_CLOCK =
                Clock.fixed(Instant.parse(FIXED_TIMESTAMP), ZoneId.of("UTC"));

        @Test
        void updatePasskeyShouldReturnSuccessOnSuccessfulResponse()
                throws IOException, InterruptedException {
            var signCount = 2;
            stubApiResponseToReturn(UPDATE_PASSKEY_URL, 204, "");

            var result =
                    passkeysService.updatePasskey(
                            PUBLIC_SUBJECT_ID,
                            SESSION_ID,
                            PASSKEY_IDENTIFIER,
                            signCount,
                            FIXED_CLOCK);

            assertTrue(result.isSuccess());
        }

        @Test
        void updatePasskeyShouldMakeTheRelevantRequestToTheAccountDataApi()
                throws IOException, InterruptedException, ExecutionException {
            stubApiResponseToReturn(UPDATE_PASSKEY_URL, 204, "");

            var signCount = 2;
            passkeysService.updatePasskey(
                    PUBLIC_SUBJECT_ID, SESSION_ID, PASSKEY_IDENTIFIER, signCount, FIXED_CLOCK);

            var httpRequestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient).send(httpRequestCaptor.capture(), ArgumentMatchers.any());
            var sentRequest = httpRequestCaptor.getValue();

            var actualRequestBody = bodyPublisherToString(sentRequest.bodyPublisher().get());
            var expectedRequestBody =
                    String.format(
                            "{\"signCount\":%d,\"lastUsedAt\":\"%s\"}", signCount, FIXED_TIMESTAMP);
            assertEquals(expectedRequestBody, actualRequestBody);
            assertEquals("PATCH", sentRequest.method());
            var expectedAuthorizationHeader =
                    Optional.of(ADAPI_BEARER_ACCESS_TOKEN.toAuthorizationHeader());
            assertEquals(
                    expectedAuthorizationHeader, sentRequest.headers().firstValue("Authorization"));
        }

        @Test
        void updatePasskeyShouldCreateAnAccessTokenWithTheRelevantData()
                throws IOException, InterruptedException {
            var signCount = 2;
            stubApiResponseToReturn(UPDATE_PASSKEY_URL, 204, "");

            passkeysService.updatePasskey(
                    PUBLIC_SUBJECT_ID, SESSION_ID, PASSKEY_IDENTIFIER, signCount, FIXED_CLOCK);

            verify(accessTokenConstructorService)
                    .createSignedAccessToken(
                            eq(PUBLIC_SUBJECT_ID),
                            eq(List.of(AccountDataScope.PASSKEY_UPDATE)),
                            eq(SESSION_ID),
                            any(),
                            any(),
                            eq(AUTH_TO_ACCOUNT_DATA_AUDIENCE),
                            eq(AUTH_ISSUER_CLAIM),
                            eq(AMC_CLIENT_ID),
                            eq(AUTH_TO_ACCOUNT_DATA_SIGNING_KEY));
        }

        private static Stream<Arguments> responseCodesAndBodiesToExpectedErrors() {

            return Stream.of(
                    Arguments.of(
                            400,
                            "{\"code\":4000,\"message\":\"Invalid request body\"}",
                            PasskeyUpdateError.PASSKEY_UPDATE_BAD_REQUEST),
                    Arguments.of(
                            403,
                            "{\"code\":4000,\"message\":\"Unauthorised\"}",
                            PasskeyUpdateError.PASSKEY_UPDATE_UNAUTHORISED),
                    Arguments.of(
                            404,
                            "{\"code\":4040,\"message\":\"Passkey not found\"}",
                            PasskeyUpdateError.PASSKEY_OR_USER_NOT_FOUND),
                    Arguments.of(
                            500,
                            "{\"code\":5000,\"message\":\"Internal server error\"}",
                            PasskeyUpdateError.PASSKEY_UPDATE_INTERNAL_SERVER_ERROR),
                    Arguments.of(
                            418,
                            "{\"code\":4180,\"message\":\"Teapot\"}",
                            PasskeyUpdateError.PASSKEY_UPDATE_UNEXPECTED_RESPONSE_CODE));
        }

        @ParameterizedTest
        @MethodSource("responseCodesAndBodiesToExpectedErrors")
        void updatePasskeyShouldHandleNon204Responses(
                int responseStatus, String responseBody, PasskeyUpdateError expectedError)
                throws IOException, InterruptedException {
            stubApiResponseToReturn(UPDATE_PASSKEY_URL, responseStatus, responseBody);

            var result =
                    passkeysService.updatePasskey(
                            PUBLIC_SUBJECT_ID, SESSION_ID, PASSKEY_IDENTIFIER, 2, FIXED_CLOCK);

            assertTrue(result.isFailure());
            assertEquals(expectedError, result.getFailure());
        }

        @Test
        void updatePasskeyShouldReturnErrorWhenTokenCreationFails()
                throws IOException, InterruptedException {
            when(accessTokenConstructorService.createSignedAccessToken(
                            any(), any(), any(), any(), any(), any(), any(), any(), any()))
                    .thenReturn(Result.failure(JwtFailureReason.SIGNING_ERROR));

            var signCount = 2;
            var result =
                    passkeysService.updatePasskey(
                            PUBLIC_SUBJECT_ID,
                            SESSION_ID,
                            PASSKEY_IDENTIFIER,
                            signCount,
                            FIXED_CLOCK);

            assertTrue(result.isFailure());
            assertEquals(PasskeyUpdateError.ERROR_CREATING_ACCESS_TOKEN, result.getFailure());

            verify(httpClient, never()).send(any(), any());
        }

        private static Stream<Arguments> exceptionsToExpectedErrors() {
            return Stream.of(
                    Arguments.of(new IOException("uh oh"), PasskeyUpdateError.IO_EXCEPTION),
                    Arguments.of(
                            new InterruptedException("uh oh"),
                            PasskeyUpdateError.INTERRUPTED_EXCEPTION));
        }

        @MethodSource("exceptionsToExpectedErrors")
        @ParameterizedTest
        void updatePasskeyShouldReturnFailureWhenAccountDataApiThrowsAnIOException(
                Exception e, PasskeyUpdateError expectedError)
                throws IOException, InterruptedException {
            when(httpClient.send(
                            argThat(
                                    request ->
                                            request.uri().equals(URI.create(UPDATE_PASSKEY_URL))),
                            any()))
                    .thenThrow(e);

            var signCount = 2;
            var result =
                    passkeysService.updatePasskey(
                            PUBLIC_SUBJECT_ID,
                            SESSION_ID,
                            PASSKEY_IDENTIFIER,
                            signCount,
                            FIXED_CLOCK);

            assertTrue(result.isFailure());

            var failure = result.getFailure();
            assertEquals(expectedError, failure);
        }
    }

    private String passkeyResponse(List<String> passkeys) {
        return """
                { "passkeys": [ %s ]
                }
                """
                .formatted(String.join(", ", passkeys));
    }

    private static String aPasskeyWithId(String id) {
        return """
                {
                    "id": "%s",
                    "credential": "credential1",
                    "aaguid": "some-aaguid",
                    "isAttested": true,
                    "signCount": 1,
                    "transports": [],
                    "isBackupEligible": true,
                    "isBackedUp": true,
                    "createdAt": "some-timestamp",
                    "lastUsedAt": "another-timestamp"
                }
                """
                .formatted(id);
    }

    private void stubApiResponseToReturn(String uri, int statusCode, String body)
            throws IOException, InterruptedException {
        when(httpResponse.body()).thenReturn(body);
        when(httpResponse.statusCode()).thenReturn(statusCode);
        when(httpClient.send(argThat(request -> request.uri().equals(URI.create(uri))), any()))
                .thenReturn(httpResponse);
    }

    private static String bodyPublisherToString(HttpRequest.BodyPublisher bodyPublisher)
            throws ExecutionException, InterruptedException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        CompletableFuture<Void> future = new CompletableFuture<>();
        bodyPublisher.subscribe(
                new Flow.Subscriber<>() {
                    @Override
                    public void onSubscribe(Flow.Subscription subscription) {
                        subscription.request(Long.MAX_VALUE);
                    }

                    @Override
                    public void onNext(ByteBuffer item) {
                        byteArrayOutputStream.write(
                                item.array(), item.arrayOffset(), item.remaining());
                    }

                    @Override
                    public void onError(Throwable throwable) {
                        future.completeExceptionally(throwable);
                    }

                    @Override
                    public void onComplete() {
                        future.complete(null);
                    }
                });
        future.get();
        return byteArrayOutputStream.toString(StandardCharsets.UTF_8);
    }
}
