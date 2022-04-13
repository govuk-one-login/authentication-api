package uk.gov.di.authentication.shared.helpers;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.AuthenticationService;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.stream.Collectors;

public class ClientSubjectHelper {

    private static final Logger LOG = LogManager.getLogger(ClientSubjectHelper.class);

    public static Subject getSubject(
            UserProfile userProfile,
            ClientRegistry client,
            AuthenticationService authenticationService) {
        if ("public".equalsIgnoreCase(client.getSubjectType())) {
            return new Subject(userProfile.getPublicSubjectID());
        } else {
            return new Subject(
                    calculatePairwiseIdentifier(
                            userProfile.getSubjectID(),
                            getSectorIdentifierForClient(client),
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

    public static String getSectorIdentifierForClient(ClientRegistry client) {
        if (!hasValidClientConfig(client)) {
            String message =
                    String.format(
                            "ClientConfig for client %s has invalid sector id.",
                            client.getClientID());
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

    public static String calculatePairwiseIdentifier(
            String subjectID, String sectorHost, byte[] salt) {
        try {
            var md = MessageDigest.getInstance("SHA-256");

            md.update(sectorHost.getBytes(StandardCharsets.UTF_8));
            md.update(subjectID.getBytes(StandardCharsets.UTF_8));

            byte[] bytes = md.digest(salt);

            var sb = new StringBuilder();
            for (byte aByte : bytes) {
                sb.append(Integer.toString((aByte & 0xff) + 0x100, 16).substring(1));
            }

            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            LOG.error("Failed to hash", e);
            throw new RuntimeException(e);
        }
    }
}
