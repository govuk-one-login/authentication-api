package uk.gov.di.orchestration.shared.api;

import java.net.URI;

public interface CommonFrontend {

    URI baseURI();

    URI ipvCallbackURI();

    URI errorURI();

    URI errorIpvCallbackURI();
}
