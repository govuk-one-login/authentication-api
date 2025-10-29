package uk.gov.di.orchestration.shared.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.net.URI;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OrchFrontendTest {

    private static final URI ORCH_FRONTEND_BASE_URI = URI.create("https://orch.frontend/");

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private OrchFrontend orchFrontend;

    @BeforeEach
    void setup() {
        when(configurationService.getOrchFrontendBaseURL()).thenReturn(ORCH_FRONTEND_BASE_URI);
        orchFrontend = new OrchFrontend(configurationService);
    }

    @Test
    void baseURIReturnsCorrectUri() {
        var expectedUri = URI.create("https://orch.frontend/");
        var actualUri = orchFrontend.baseURI();
        assertThat(actualUri, equalTo(expectedUri));
    }

    @Test
    void ipvCallbackURIReturnsCorrectUri() {
        var expectedUri = URI.create("https://orch.frontend/ipv-callback");
        var actualUri = orchFrontend.ipvCallbackURI();
        assertThat(actualUri, equalTo(expectedUri));
    }

    @Test
    void errorURIReturnsCorrectUri() {
        var expectedUri = URI.create("https://orch.frontend/error");
        var actualUri = orchFrontend.errorURI();
        assertThat(actualUri, equalTo(expectedUri));
    }

    @Test
    void errorIpvCallbackURIReturnsCorrectUri() {
        var expectedUri = URI.create("https://orch.frontend/ipv-callback-session-expiry-error");
        var actualUri = orchFrontend.errorIpvCallbackURI();
        assertThat(actualUri, equalTo(expectedUri));
    }
}
