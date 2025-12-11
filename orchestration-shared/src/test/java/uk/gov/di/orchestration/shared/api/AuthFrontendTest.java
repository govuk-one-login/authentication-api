package uk.gov.di.orchestration.shared.api;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.openid.connect.sdk.Prompt;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.net.URI;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.aMapWithSize;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasEntry;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.matchers.UriMatcher.baseUri;
import static uk.gov.di.orchestration.sharedtest.matchers.UriMatcher.queryParameters;

// QualityGateUnitTest
class AuthFrontendTest {

    private static final URI AUTH_FRONTEND_BASE_URI = URI.create("https://auth.frontend/");

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private AuthFrontend authFrontend;

    @BeforeEach
    void setup() {
        when(configurationService.getAuthFrontendBaseURL()).thenReturn(AUTH_FRONTEND_BASE_URI);
        authFrontend = new AuthFrontend(configurationService);
    }

    // QualityGateRegressionTest
    @Test
    void baseURIReturnsCorrectUri() {
        var expectedUri = URI.create("https://auth.frontend/");
        var actualUri = authFrontend.baseURI();
        assertThat(actualUri, equalTo(expectedUri));
    }

    // QualityGateRegressionTest
    @Test
    void privacyNoticeURIReturnsCorrectUri() {
        var expectedUri = URI.create("https://auth.frontend/privacy-notice");
        var actualUri = authFrontend.privacyNoticeURI();
        assertThat(actualUri, equalTo(expectedUri));
    }

    // QualityGateRegressionTest
    @Test
    void termsOfServiceURIReturnsCorrectUri() {
        var expectedUri = URI.create("https://auth.frontend/terms-and-conditions");
        var actualUri = authFrontend.termsOfServiceURI();
        assertThat(actualUri, equalTo(expectedUri));
    }

    // QualityGateRegressionTest
    @Test
    void ipvCallbackURIReturnsCorrectUri() {
        var expectedUri = URI.create("https://auth.frontend/ipv-callback");
        var actualUri = authFrontend.ipvCallbackURI();
        assertThat(actualUri, equalTo(expectedUri));
    }

    // QualityGateRegressionTest
    @ParameterizedTest
    @MethodSource("authorizeURICases")
    void authorizeURIReturnsCorrectUri(
            Optional<Prompt.Type> prompt,
            Optional<String> googleAnalytics,
            Map<String, String> expectedQueryParameters) {
        var expectedBaseUri = URI.create("https://auth.frontend/authorize");
        var actualUri = authFrontend.authorizeURI(prompt, googleAnalytics);
        assertThat(actualUri, baseUri(expectedBaseUri));
        assertThat(actualUri, queryParameters(aMapWithSize(expectedQueryParameters.size())));
        for (var entry : expectedQueryParameters.entrySet()) {
            assertThat(actualUri, queryParameters(hasEntry(entry.getKey(), entry.getValue())));
        }
    }

    static Stream<Arguments> authorizeURICases() {
        return Stream.of(
                Arguments.of(Optional.empty(), Optional.empty(), Map.of()),
                Arguments.of(
                        Optional.of(Prompt.Type.LOGIN),
                        Optional.empty(),
                        Map.of("prompt", "login")),
                Arguments.of(Optional.empty(), Optional.of("sign-in"), Map.of("result", "sign-in")),
                Arguments.of(
                        Optional.of(Prompt.Type.LOGIN),
                        Optional.of("sign-in"),
                        Map.of(
                                "prompt", "login",
                                "result", "sign-in")));
    }

    // QualityGateRegressionTest
    @Test
    void defaultLogoutURIReturnsCorrectUri() {
        var expectedUri = URI.create("https://auth.frontend/signed-out");
        var actualUri = authFrontend.defaultLogoutURI();
        assertThat(actualUri, equalTo(expectedUri));
    }

    // QualityGateRegressionTest
    @Test
    void errorLogoutURIReturnsCorrectUri() {
        var error = new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, "invalid session");
        var actualUri = authFrontend.errorLogoutURI(error);
        var expectedBaseUri = URI.create("https://auth.frontend/signed-out");
        var expectedQueryParameters =
                Map.of(
                        "error_description", "invalid session",
                        "error_code", "invalid_request");
        assertThat(actualUri, baseUri(expectedBaseUri));
        assertThat(actualUri, queryParameters(aMapWithSize(expectedQueryParameters.size())));
        for (var entry : expectedQueryParameters.entrySet()) {
            assertThat(actualUri, queryParameters(hasEntry(entry.getKey(), entry.getValue())));
        }
    }

    // QualityGateRegressionTest
    @Test
    void accountSuspendedURIReturnsCorrectUri() {
        var expectedUri = URI.create("https://auth.frontend/unavailable-temporary");
        var actualUri = authFrontend.accountSuspendedURI();
        assertThat(actualUri, equalTo(expectedUri));
    }

    // QualityGateRegressionTest
    @Test
    void errorURIReturnsCorrectUri() {
        var expectedUri = URI.create("https://auth.frontend/error");
        var actualUri = authFrontend.errorURI();
        assertThat(actualUri, equalTo(expectedUri));
    }

    // QualityGateRegressionTest
    @Test
    void errorIpvCallbackURIReturnsCorrectUri() {
        var expectedUri = URI.create("https://auth.frontend/ipv-callback-session-expiry-error");
        var actualUri = authFrontend.errorIpvCallbackURI();
        assertThat(actualUri, equalTo(expectedUri));
    }
}
