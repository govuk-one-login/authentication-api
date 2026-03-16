package uk.gov.di.authentication.frontendapi.services.passkeys;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.PUBLIC_SUBJECT_ID;

class PasskeysServiceTest {
    ConfigurationService configurationService = mock(ConfigurationService.class);
    HttpClient httpClient = mock(HttpClient.class);
    HttpResponse httpResponse = mock(HttpResponse.class);
    PasskeysService passkeysService = new PasskeysService(configurationService, httpClient);

    private static final String ACCOUNT_DATA_BASE_URI = "https://example.com";
    private static final String EXPECTED_REQUEST_URL =
            "%s/accounts/%s/authenticators/passkeys"
                    .formatted(ACCOUNT_DATA_BASE_URI, PUBLIC_SUBJECT_ID);

    @BeforeEach
    void beforeEach() {
        when(configurationService.getAccountDataURI()).thenReturn(ACCOUNT_DATA_BASE_URI);
    }

    @AfterEach
    void afterEach() {
        reset(httpClient, configurationService, httpResponse);
    }

    private static Stream<Arguments> successfulTestCases() {
        return Stream.of(
                Arguments.of(List.of(aPasskeyWithId("123456")), true),
                Arguments.of(List.of(aPasskeyWithId("123456"), aPasskeyWithId("456789")), true),
                Arguments.of(List.of(), false));
    }

    @MethodSource("successfulTestCases")
    @ParameterizedTest
    void shouldReturnTheExpectedResultForASuccessfulPasskeysResponse(
            List<String> returnedPasskeys, boolean expectedResult)
            throws IOException, InterruptedException {
        when(httpResponse.body()).thenReturn(passkeyResponse(returnedPasskeys));
        when(httpClient.send(
                        argThat(request -> request.uri().equals(URI.create(EXPECTED_REQUEST_URL))),
                        any()))
                .thenReturn(httpResponse);

        var hasActivePasskey = passkeysService.hasActivePasskey(PUBLIC_SUBJECT_ID);

        assertEquals(expectedResult, hasActivePasskey);
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
}
