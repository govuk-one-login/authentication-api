package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.ClientStartInfo;
import uk.gov.di.authentication.frontendapi.entity.UserStartInfo;
import uk.gov.di.authentication.shared.conditions.ConsentHelper;
import uk.gov.di.authentication.shared.conditions.IdentityHelper;
import uk.gov.di.authentication.shared.conditions.UpliftHelper;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;

public class StartService {

    private final ClientService clientService;
    private final DynamoService dynamoService;
    private static final String CLIENT_ID_PARAM = "client_id";
    private static final Logger LOG = LogManager.getLogger(StartService.class);

    public StartService(ClientService clientService, DynamoService dynamoService) {
        this.clientService = clientService;
        this.dynamoService = dynamoService;
    }

    public UserContext buildUserContext(Session session, ClientSession clientSession) {
        var builder = UserContext.builder(session).withClientSession(clientSession);
        UserContext userContext;
        try {
            var clientId =
                    clientSession.getAuthRequestParams().get(CLIENT_ID_PARAM).stream()
                            .findFirst()
                            .orElseThrow();
            var clientRegistry = clientService.getClient(clientId).orElseThrow();
            Optional.of(session)
                    .map(Session::getEmailAddress)
                    .flatMap(dynamoService::getUserProfileByEmailMaybe)
                    .ifPresent(builder::withUserProfile);
            userContext = builder.withClient(clientRegistry).build();
        } catch (NoSuchElementException e) {
            LOG.error("Error creating UserContext");
            throw new RuntimeException("Error when creating UserContext", e);
        }
        return userContext;
    }

    public ClientStartInfo buildClientStartInfo(UserContext userContext) throws ParseException {
        AuthenticationRequest authenticationRequest;
        try {
            authenticationRequest =
                    AuthenticationRequest.parse(
                            userContext.getClientSession().getAuthRequestParams());
        } catch (ParseException e) {
            throw new ParseException("Unable to parse authentication request");
        }
        var scopes = authenticationRequest.getScope().toStringList();
        var clientRegistry = userContext.getClient().orElseThrow();
        var clientInfo =
                new ClientStartInfo(
                        clientRegistry.getClientName(),
                        scopes,
                        clientRegistry.getServiceType(),
                        clientRegistry.isCookieConsentShared());
        LOG.info(
                "Found ClientStartInfo for ClientName: {} Scopes: {} ServiceType: {}",
                clientRegistry.getClientName(),
                scopes,
                clientRegistry.getServiceType());

        return clientInfo;
    }

    public UserStartInfo buildUserStartInfo(UserContext userContext) {
        var consentRequired = ConsentHelper.userHasNotGivenConsent(userContext);
        var uplift = false;
        if (Objects.nonNull(userContext.getSession().getCurrentCredentialStrength())) {
            uplift = UpliftHelper.upliftRequired(userContext);
        }
        var identityRequired =
                IdentityHelper.identityRequired(
                        userContext.getClientSession().getAuthRequestParams());

        LOG.info(
                "Found UserStartInfo for ConsentRequired: {} UpliftRequired: {} IdentityRequired: {}",
                consentRequired,
                uplift,
                identityRequired);

        return new UserStartInfo(consentRequired, uplift, identityRequired);
    }
}
