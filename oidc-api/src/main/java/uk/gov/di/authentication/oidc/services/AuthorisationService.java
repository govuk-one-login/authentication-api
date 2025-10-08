package uk.gov.di.authentication.oidc.services;

import com.nimbusds.oauth2.sdk.ParseException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.exceptions.IncorrectRedirectUriException;
import uk.gov.di.authentication.oidc.exceptions.InvalidAuthenticationRequestException;
import uk.gov.di.authentication.oidc.exceptions.MissingClientIDException;
import uk.gov.di.authentication.oidc.exceptions.MissingRedirectUriException;
import uk.gov.di.orchestration.shared.exceptions.ClientNotFoundException;
import uk.gov.di.orchestration.shared.services.ClientService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;

public class AuthorisationService {
    private final ClientService clientService;
    private static final Logger LOG = LogManager.getLogger(AuthorisationService.class);

    public AuthorisationService(ClientService clientService) {
        this.clientService = clientService;
    }

    public AuthorisationService(ConfigurationService configurationService) {
        this.clientService = new DynamoClientService(configurationService);
    }

    public void classifyParseException(ParseException error)
            throws MissingClientIDException,
                    IncorrectRedirectUriException,
                    ClientNotFoundException,
                    InvalidAuthenticationRequestException,
                    MissingRedirectUriException {
        if (error.getClientID() == null) {
            throw new MissingClientIDException(error.getErrorObject());
        }

        if (error.getRedirectionURI() == null) {
            throw new MissingRedirectUriException(error.getErrorObject());
        }

        var client =
                clientService
                        .getClient(error.getClientID().getValue())
                        .orElseThrow(
                                () -> new ClientNotFoundException(error.getClientID().getValue()));

        if (!client.getRedirectUrls().contains(error.getRedirectionURI().toString())) {
            LOG.warn("Redirect URI {} is invalid for client", error.getRedirectionURI());
            throw new IncorrectRedirectUriException(error.getErrorObject());
        }

        throw new InvalidAuthenticationRequestException(error.getErrorObject());
    }
}
