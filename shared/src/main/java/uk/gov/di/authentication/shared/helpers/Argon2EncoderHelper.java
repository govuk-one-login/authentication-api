package uk.gov.di.authentication.shared.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.security.SecureRandom;
import java.util.Base64;

public class Argon2EncoderHelper {

    private static final Logger LOG = LogManager.getLogger(Argon2EncoderHelper.class);

    private static final Base64.Encoder BASE64_ENCODER = Base64.getEncoder().withoutPadding();
    private static final SecureRandom RANDOM = new SecureRandom();

    public static String argon2Hash(String raw) {
        var config = ConfigurationService.getInstance();
        int memoryInKibibytes = config.getArgon2MemoryInKibibytes();
        int iterations = config.getArgon2Iterations();
        int parallelism = config.getArgon2Parallelism();

        LOG.info("Argon2id config: m={}, t={}, p={}", memoryInKibibytes, iterations, parallelism);

        byte[] salt = new byte[32];
        RANDOM.nextBytes(salt);

        var parameters =
                new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                        .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                        .withIterations(iterations)
                        .withSalt(salt)
                        .withMemoryAsKB(memoryInKibibytes)
                        .withParallelism(parallelism)
                        .build();

        var generator = new Argon2BytesGenerator();
        generator.init(parameters);
        generator.generateBytes(raw.toCharArray(), salt);

        return encode(salt, parameters);
    }

    private static String encode(byte[] hash, Argon2Parameters parameters)
            throws IllegalArgumentException {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("$argon2id");
        stringBuilder
                .append("$v=")
                .append(parameters.getVersion())
                .append("$m=")
                .append(parameters.getMemory())
                .append(",t=")
                .append(parameters.getIterations())
                .append(",p=")
                .append(parameters.getLanes());
        if (parameters.getSalt() != null) {
            stringBuilder.append("$").append(BASE64_ENCODER.encodeToString(parameters.getSalt()));
        }
        stringBuilder.append("$").append(BASE64_ENCODER.encodeToString(hash));
        return stringBuilder.toString();
    }
}
