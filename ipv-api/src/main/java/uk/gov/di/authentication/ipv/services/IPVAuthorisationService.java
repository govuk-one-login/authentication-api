package uk.gov.di.authentication.ipv.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.Optional;

public class IPVAuthorisationService {

    private static final Logger LOG = LogManager.getLogger(IPVAuthorisationService.class);
    private final ConfigurationService configurationService;
    private final RedisConnectionService redisConnectionService;
    public static final String STATE_STORAGE_PREFIX = "state:";

    public IPVAuthorisationService(
            ConfigurationService configurationService,
            RedisConnectionService redisConnectionService) {
        this.configurationService = configurationService;
        this.redisConnectionService = redisConnectionService;
    }

    public Optional<ErrorObject> validateResponse(Map<String, String> headers, String sessionId) {
        if (headers == null || headers.isEmpty()) {
            LOG.warn("No Query parameters in IPV Authorisation response");
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE, "No query parameters present"));
        }
        if (headers.containsKey("error")) {
            LOG.warn("Error response found in IPV Authorisation response");
            return Optional.of(new ErrorObject(headers.get("error")));
        }
        if (!headers.containsKey("state") || headers.get("state").isEmpty()) {
            LOG.warn("No state param in IPV Authorisation response");
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "No state param present in Authorisation response"));
        }
        if (!isStateValid(sessionId, headers.get("state"))) {
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "Invalid state param present in Authorisation response"));
        }
        if (!headers.containsKey("code") || headers.get("code").isEmpty()) {
            LOG.warn("No code param in IPV Authorisation response");
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "No code param present in Authorisation response"));
        }

        return Optional.empty();
    }

    public void storeState(String sessionId, State state) {
        try {
            redisConnectionService.saveWithExpiry(
                    STATE_STORAGE_PREFIX + sessionId,
                    new ObjectMapper().writeValueAsString(state),
                    configurationService.getSessionExpiry());
        } catch (JsonProcessingException e) {
            LOG.error("Unable to save state to Redis");
            throw new RuntimeException(e);
        }
    }

    private boolean isStateValid(String sessionId, String responseState) {
        var value =
                Optional.ofNullable(
                        redisConnectionService.getValue(STATE_STORAGE_PREFIX + sessionId));
        if (value.isEmpty()) {
            LOG.info("No state found in Redis");
            return false;
        }
        State storedState;
        try {
            storedState = new ObjectMapper().readValue(value.get(), State.class);
        } catch (JsonProcessingException e) {
            LOG.info("Error when deserializing state from redis");
            return false;
        }
        LOG.info(
                "Response state: {} and Stored state: {}. Are equal: {}",
                responseState,
                storedState.getValue(),
                responseState.equals(storedState.getValue()));
        return responseState.equals(storedState.getValue());
    }

    public Subject getPairwiseSubject(UserProfile userProfile, ClientRegistry client) {
        if (client.getSubjectType().equalsIgnoreCase("public")) {
            return new Subject(userProfile.getPublicSubjectID());
        } else {
            String uri =
                    client.getSectorIdentifierUri() != null
                            ? client.getSectorIdentifierUri()
                            : returnHost(client);
            return new Subject(
                    ClientSubjectHelper.pairwiseIdentifier(userProfile.getSubjectID(), uri));
        }
    }

    private String returnHost(ClientRegistry clientRegistry) {
        String redirectUri = null;

        if (clientRegistry.getRedirectUrls().stream().findFirst().isPresent()) {
            redirectUri = clientRegistry.getRedirectUrls().stream().findFirst().get();
            try {
                String hostname = new URI(redirectUri).getHost();
                if (hostname != null)
                    return hostname.startsWith("www.") ? hostname.substring(4) : hostname;
            } catch (URISyntaxException e) {
                LOG.info("Not a valid URI {} - Exception {}", redirectUri, e);
            }
        }

        return redirectUri;
    }
}
