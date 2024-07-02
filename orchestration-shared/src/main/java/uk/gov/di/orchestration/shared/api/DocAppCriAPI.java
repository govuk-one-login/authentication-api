package uk.gov.di.orchestration.shared.api;

import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.net.URI;

import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;

public class DocAppCriAPI {

    public final URI baseUri;
    public final String criDataEndpoint;

    public DocAppCriAPI(ConfigurationService configurationService) {
        this.baseUri = configurationService.getDocAppBackendURI();
        this.criDataEndpoint = configurationService.getDocAppCriV2DataEndpoint();
    }

    public URI tokenURI() {
        return buildURI(baseUri, "token");
    }

    public URI criDataURI() {
        return buildURI(baseUri, criDataEndpoint);
    }
}
