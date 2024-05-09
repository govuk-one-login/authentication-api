package uk.gov.di.orchestration.shared.api;

import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.net.URI;

import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;

public class DocAppBackendAPI {

    public final URI docAppBackendUri;
    public final String criDataEndpoint;

    public static final String TOKEN_ENDPOINT = "token";

    public DocAppBackendAPI(ConfigurationService configurationService) {
        this.docAppBackendUri = configurationService.getDocAppBackendURI();
        this.criDataEndpoint = configurationService.getDocAppCriV2DataEndpoint();
    }

    public URI tokenURI() {
        return buildURI(docAppBackendUri, TOKEN_ENDPOINT);
    }

    public URI criDataURI() {
        return buildURI(docAppBackendUri, criDataEndpoint);
    }
}
