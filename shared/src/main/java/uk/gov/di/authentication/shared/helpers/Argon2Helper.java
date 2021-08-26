package uk.gov.di.authentication.shared.helpers;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

public class Argon2Helper {

    private static final int MEMORY_IN_KIBIBYTES = 15360;
    private static final int PARALLELISM = 1;
    private static final int ITERATIONS = 2;

    public static byte[] argon2Hash(byte[] input) {
        byte[] result = new byte[32];

        var parameters =
                new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                        .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                        .withIterations(ITERATIONS)
                        .withMemoryAsKB(MEMORY_IN_KIBIBYTES)
                        .withParallelism(PARALLELISM)
                        .build();

        var generator = new Argon2BytesGenerator();
        generator.init(parameters);
        generator.generateBytes(input, result, 0, result.length);

        return result;
    }
}
