package uk.gov.di.authentication.shared.helpers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ClientSubjectHelper {

    private static final Logger LOGGER = LoggerFactory.getLogger(ClientSubjectHelper.class);

    private static final ConfigurationService configurationService = new ConfigurationService();

    public static String pairwiseIdentifier(String subjectID, String sector) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            md.update(sector.getBytes(StandardCharsets.UTF_8));
            md.update(subjectID.getBytes(StandardCharsets.UTF_8));

            byte[] bytes = md.digest(configurationService.getSalt());

            StringBuilder sb = new StringBuilder();
            for (byte aByte : bytes) {
                sb.append(Integer.toString((aByte & 0xff) + 0x100, 16).substring(1));
            }

            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
