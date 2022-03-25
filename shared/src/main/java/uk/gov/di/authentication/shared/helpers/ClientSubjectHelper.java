package uk.gov.di.authentication.shared.helpers;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.AuthenticationService;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.NoSuchElementException;

public class ClientSubjectHelper {

    private static final Logger LOG = LogManager.getLogger(ClientSubjectHelper.class);

    public static Subject getSubject(
            UserProfile userProfile,
            ClientRegistry client,
            AuthenticationService authenticationService) {
        if (client.getSubjectType().equalsIgnoreCase("public")) {
            return new Subject(userProfile.getPublicSubjectID());
        } else {
            var uri =
                    client.getSectorIdentifierUri() != null
                            ? client.getSectorIdentifierUri()
                            : returnHost(client);
            return new Subject(
                    calculatePairwiseIdentifier(
                            userProfile.getSubjectID(),
                            uri,
                            authenticationService.getOrGenerateSalt(userProfile)));
        }
    }

    private static String returnHost(ClientRegistry clientRegistry) {
        String redirectUri;
        try {
            redirectUri = clientRegistry.getRedirectUrls().stream().findFirst().orElseThrow();
        } catch (NoSuchElementException e) {
            LOG.warn("Client Registry contains no redirect URLs");
            throw new RuntimeException(e);
        }
        try {
            var hostname = new URI(redirectUri).getHost();
            if (hostname != null)
                return hostname.startsWith("www.") ? hostname.substring(4) : hostname;
        } catch (URISyntaxException e) {
            LOG.info("Not a valid URI {} - Exception {}", redirectUri, e);
        }
        return redirectUri;
    }

    public static String calculatePairwiseIdentifier(String subjectID, String sector, byte[] salt) {
        try {
            var md = MessageDigest.getInstance("SHA-256");

            md.update(sector.getBytes(StandardCharsets.UTF_8));
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
