package uk.gov.di.authentication.shared.helpers;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jose4j.base64url.Base64Url;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.AuthenticationService;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.stream.Collectors;

import static com.nimbusds.openid.connect.sdk.SubjectType.PUBLIC;

public class ClientSubjectHelper {

    private static final Logger LOG = LogManager.getLogger(ClientSubjectHelper.class);
    private static final String PAIRWISE_PREFIX = "urn:fdc:gov.uk:2022:";

    public static Subject getSubject(
            UserProfile userProfile,
            ClientRegistry client,
            AuthSessionItem authSession,
            AuthenticationService authenticationService) {
        if (PUBLIC.toString().equalsIgnoreCase(authSession.getSubjectType())) {
            return new Subject(userProfile.getPublicSubjectID());
        } else {
            return new Subject(
                    calculatePairwiseIdentifier(
                            userProfile.getSubjectID(),
                            authSession.getRpSectorIdentifierHost(),
                            authenticationService.getOrGenerateSalt(userProfile)));
        }
    }

    public static Subject getSubjectWithSectorIdentifier(
            UserProfile userProfile,
            String sectorIdentifierURI,
            AuthenticationService authenticationService) {
        return new Subject(
                calculatePairwiseIdentifier(
                        userProfile.getSubjectID(),
                        returnHost(sectorIdentifierURI),
                        authenticationService.getOrGenerateSalt(userProfile)));
    }

    public static String getSectorIdentifierForClient(
            ClientRegistry client, AuthSessionItem authSession, String internalSectorUri) {
        if (authSession.getIsOneLoginService()) {
            return returnHost(internalSectorUri);
        }
        if (!hasValidClientConfig(client)) {
            String message =
                    String.format(
                            "ClientConfig for client %s has invalid sector id.",
                            authSession.getClientId());
            LOG.error(message);
            throw new RuntimeException(message);
        }
        return client.getSectorIdentifierUri() != null
                ? returnHost(client.getSectorIdentifierUri())
                : returnHost(client.getRedirectUrls().stream().findFirst().orElseThrow());
    }

    static boolean hasValidClientConfig(ClientRegistry client) {
        if (client.getRedirectUrls().size() > 1 && client.getSectorIdentifierUri() == null) {
            return client.getRedirectUrls().stream()
                            .map(ClientSubjectHelper::returnHost)
                            .collect(Collectors.toSet())
                            .size()
                    == 1;
        } else {
            return true;
        }
    }

    static String returnHost(String uri) {
        try {
            var hostname = URI.create(uri).getHost();
            return hostname.startsWith("www.") ? hostname.substring(4) : hostname;
        } catch (IllegalArgumentException | NullPointerException e) {
            LOG.error("Not a valid URI {} - Exception {}", uri, e);
            throw new RuntimeException(e);
        }
    }

    public static String calculatePairwiseIdentifier(String subjectID, URI uri, byte[] salt) {
        var host = returnHost(uri.toString());
        return calculatePairwiseIdentifier(subjectID, host, salt);
    }

    public static String calculatePairwiseIdentifier(
            String subjectID, String sectorHost, byte[] salt) {
        try {
            var md = MessageDigest.getInstance("SHA-256");

            md.update(sectorHost.getBytes(StandardCharsets.UTF_8));
            md.update(subjectID.getBytes(StandardCharsets.UTF_8));

            byte[] bytes = md.digest(salt);

            var sb = Base64Url.encode(bytes);

            return PAIRWISE_PREFIX + sb;
        } catch (NoSuchAlgorithmException e) {
            LOG.error("Failed to hash", e);
            throw new RuntimeException(e);
        }
    }
}
