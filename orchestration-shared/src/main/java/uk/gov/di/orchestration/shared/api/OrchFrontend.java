package uk.gov.di.orchestration.shared.api;

import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.net.URI;

import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;

public class OrchFrontend implements CommonFrontend {

    private final URI orchFrontendBaseUri;

    public OrchFrontend(ConfigurationService configurationService) {
        orchFrontendBaseUri = configurationService.getOrchFrontendBaseURL();
    }

    public URI baseURI() {
        return orchFrontendBaseUri;
    }

    public URI ipvCallbackURI() {
        return buildURI(orchFrontendBaseUri, "ipv-callback");
    }

    public URI errorURI() {
        return buildURI(orchFrontendBaseUri, "error");
    }

    public URI errorIpvCallbackURI() {
        return buildURI(orchFrontendBaseUri, "ipv-callback-session-expiry-error");
    }
}
