package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.helpers.IdGenerator;

import java.security.SecureRandom;

import static java.lang.String.format;

public class CodeGeneratorService {

    private static final SecureRandom RANDOM = new SecureRandom();

    public String sixDigitCode() {
        return format("%06d", RANDOM.nextInt(999999));
    }

    public String twentyByteEncodedRandomCode() {
        return IdGenerator.generate();
    }
}
