package uk.gov.di.authentication.oidc.services;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.exceptions.IncorrectRedirectUriException;
import uk.gov.di.authentication.oidc.exceptions.InvalidAuthenticationRequestException;
import uk.gov.di.authentication.oidc.exceptions.MissingClientIDException;
import uk.gov.di.authentication.oidc.exceptions.MissingRedirectUriException;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.exceptions.ClientNotFoundException;
import uk.gov.di.orchestration.shared.services.ClientService;

import java.net.URI;
import java.util.List;
import java.util.Optional;

import static java.lang.String.format;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthorisationServiceTest {
    private AuthorisationService authorisationService;
    private final ClientService clientService = mock(ClientService.class);

    private static final ClientID CLIENT_ID = new ClientID("test-id");
    private static final URI REDIRECT_URI = URI.create("https://localhost:8080");

    @BeforeEach
    void setUp() {
        authorisationService = new AuthorisationService(clientService);

        when(clientService.getClient(anyString()))
                .thenReturn(
                        Optional.of(
                                new ClientRegistry()
                                        .withClientID(CLIENT_ID.getValue())
                                        .withRedirectUrls(List.of(REDIRECT_URI.toString()))));
    }

    @Test
    void classifyParseExceptionShouldReturnMissingRedirectUriExceptionWhenNoRedirectUri() {
        assertThrows(
                MissingRedirectUriException.class,
                () ->
                        authorisationService.classifyParseException(
                                new ParseException(
                                        "Missing redirect_uri parameter",
                                        OAuth2Error.INVALID_REQUEST,
                                        CLIENT_ID,
                                        null,
                                        null,
                                        null)));
    }

    @Test
    void classifyParseExceptionShouldReturnMissingClientIDExceptionWhenNoClientId() {
        assertThrows(
                MissingClientIDException.class,
                () ->
                        authorisationService.classifyParseException(
                                new ParseException(
                                        "Missing client_id parameter",
                                        OAuth2Error.INVALID_REQUEST,
                                        null,
                                        REDIRECT_URI,
                                        null,
                                        null)));
    }

    @Test
    void classifyParseExceptionShouldReturnClientNotFoundExceptionWhenClientIdButNoClient() {
        when(clientService.getClient(CLIENT_ID.getValue())).thenReturn(Optional.empty());

        assertThrows(
                ClientNotFoundException.class,
                () ->
                        authorisationService.classifyParseException(
                                new ParseException(
                                        "Invalid request",
                                        OAuth2Error.INVALID_REQUEST,
                                        CLIENT_ID,
                                        REDIRECT_URI,
                                        null,
                                        null)),
                format("No Client found for ClientID: %s", CLIENT_ID));
    }

    @Test
    void
            classifyParseExceptionShouldReturnInvalidAuthenticationRequestExceptionWhenRedirectUrlIsCorrect() {
        assertThrows(
                InvalidAuthenticationRequestException.class,
                () ->
                        authorisationService.classifyParseException(
                                new ParseException(
                                        "Invalid request",
                                        OAuth2Error.INVALID_REQUEST,
                                        CLIENT_ID,
                                        REDIRECT_URI,
                                        null,
                                        null)));
    }

    @Test
    void
            classifyParseExceptionShouldReturnIncorrectRedirectUriExceptionWhenRedirectUrlIsIncorrect() {
        assertThrows(
                IncorrectRedirectUriException.class,
                () ->
                        authorisationService.classifyParseException(
                                new ParseException(
                                        "Invalid request",
                                        OAuth2Error.INVALID_REQUEST,
                                        CLIENT_ID,
                                        URI.create("invalid-uri"),
                                        null,
                                        null)));
    }
}
