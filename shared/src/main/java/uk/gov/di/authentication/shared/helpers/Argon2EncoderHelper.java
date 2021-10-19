package uk.gov.di.authentication.shared.helpers;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.util.Base64;

public class Argon2EncoderHelper {

    private static final int MEMORY_IN_KIBIBYTES = 15360;
    private static final int PARALLELISM = 1;
    private static final int ITERATIONS = 2;
    private static final Base64.Encoder BASE64_ENCODER = Base64.getEncoder().withoutPadding();

    public static String argon2Hash(String raw) {
        byte[] salt = new byte[32];

        var parameters =
                new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                        .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                        .withIterations(ITERATIONS)
                        .withSalt(salt)
                        .withMemoryAsKB(MEMORY_IN_KIBIBYTES)
                        .withParallelism(PARALLELISM)
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
