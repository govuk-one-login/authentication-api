package uk.gov.di.orchestration.shared.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jose4j.base64url.Base64Url;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.stream.Collectors;

public class ClientSubjectHelper {

    private static final Logger LOG = LogManager.getLogger(ClientSubjectHelper.class);
    private static final String PAIRWISE_PREFIX = "urn:fdc:gov.uk:2022:";
    private static final String WALLET_PAIRWISE_PREFIX = "urn:fdc:wallet.account.gov.uk:2024:";

    public static String getSectorIdentifierForClient(
            ClientRegistry client, String internalSectorUri) {
        if (client.isOneLoginService()) {
            return returnHost(internalSectorUri);
        }
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

    public static String calculatePairwiseIdentifier(String subjectID, URI uri, byte[] salt) {
        var host = returnHost(uri.toString());
        return calculatePairwiseIdentifier(subjectID, host, salt);
    }

    public static String calculatePairwiseIdentifier(
            String subjectID, String sectorHost, byte[] salt) {
        var md = getMessageDigest(sectorHost, subjectID);
        byte[] bytes = md.digest(salt);
        var sb = Base64Url.encode(bytes);
        return PAIRWISE_PREFIX + sb;
    }

    public static String calculateWalletSubjectIdentifier(String sectorID, String commonSubjectID) {
        var md = getMessageDigest(sectorID, commonSubjectID);
        byte[] bytes = md.digest();
        var sb = Base64Url.encode(bytes);
        return WALLET_PAIRWISE_PREFIX + sb;
    }

    private static MessageDigest getMessageDigest(String sectorHost, String subjectID) {
        try {
            var md = MessageDigest.getInstance("SHA-256");

            md.update(sectorHost.getBytes(StandardCharsets.UTF_8));
            md.update(subjectID.getBytes(StandardCharsets.UTF_8));

            return md;
        } catch (NoSuchAlgorithmException e) {
            LOG.error("Failed to hash", e);
            throw new RuntimeException(e);
        }
    }
}
