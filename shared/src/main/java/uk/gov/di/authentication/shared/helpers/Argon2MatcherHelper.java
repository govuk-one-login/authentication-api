package uk.gov.di.authentication.shared.helpers;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.Arrays;

import java.util.Base64;

public class Argon2MatcherHelper {

    private static final Base64.Decoder BASE64_DECODER = Base64.getDecoder();

    public static boolean matchRawStringWithEncoded(String rawPassword, String encodedPassword) {
        Argon2Hash decoded;
        try {
            decoded = decode(encodedPassword);
        } catch (IllegalArgumentException ex) {
            return false;
        }
        byte[] hashBytes = new byte[decoded.getHash().length];
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(decoded.getParameters());
        generator.generateBytes(rawPassword.toCharArray(), hashBytes);
        return constantTimeArrayEquals(decoded.getHash(), hashBytes);
    }

    private static boolean constantTimeArrayEquals(byte[] expected, byte[] actual) {
        if (expected.length != actual.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < expected.length; i++) {
            result |= expected[i] ^ actual[i];
        }
        return result == 0;
    }

    private static Argon2Hash decode(String encodedHash) throws IllegalArgumentException {
        Argon2Parameters.Builder paramsBuilder;
        String[] parts = encodedHash.split("\\$");
        if (parts.length < 4) {
            throw new IllegalArgumentException("Invalid encoded Argon2-hash");
        }
        int currentPart = 2;
        paramsBuilder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id);
        if (parts[currentPart].startsWith("v=")) {
            paramsBuilder.withVersion(Integer.parseInt(parts[currentPart].substring(2)));
            currentPart++;
        }
        String[] performanceParams = parts[currentPart++].split(",");
        if (performanceParams.length != 3) {
            throw new IllegalArgumentException("Amount of performance parameters invalid");
        }
        if (!performanceParams[0].startsWith("m=")) {
            throw new IllegalArgumentException("Invalid memory parameter");
        }
        paramsBuilder.withMemoryAsKB(Integer.parseInt(performanceParams[0].substring(2)));
        if (!performanceParams[1].startsWith("t=")) {
            throw new IllegalArgumentException("Invalid iterations parameter");
        }
        paramsBuilder.withIterations(Integer.parseInt(performanceParams[1].substring(2)));
        if (!performanceParams[2].startsWith("p=")) {
            throw new IllegalArgumentException("Invalid parallelity parameter");
        }
        paramsBuilder.withParallelism(Integer.parseInt(performanceParams[2].substring(2)));
        paramsBuilder.withSalt(BASE64_DECODER.decode(parts[currentPart++]));
        return new Argon2Hash(BASE64_DECODER.decode(parts[currentPart]), paramsBuilder.build());
    }

    private static class Argon2Hash {

        private byte[] hash;

        private Argon2Parameters parameters;

        Argon2Hash(byte[] hash, Argon2Parameters parameters) {
            this.hash = Arrays.clone(hash);
            this.parameters = parameters;
        }

        public byte[] getHash() {
            return Arrays.clone(this.hash);
        }

        public Argon2Parameters getParameters() {
            return this.parameters;
        }

        public void setParameters(Argon2Parameters parameters) {
            this.parameters = parameters;
        }
    }
}
