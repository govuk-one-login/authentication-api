package uk.gov.di.orchestration.shared.utils;

import uk.gov.di.orchestration.shared.entity.IdentityProgressStatus;
import uk.gov.di.orchestration.shared.entity.OrchIdentityCredentials;
import uk.gov.di.orchestration.shared.entity.ProcessingIdentityStatus;

import java.util.Objects;
import java.util.Optional;

public class IdentityProgressUtils {
    private IdentityProgressUtils() {}

    public static ProcessingIdentityStatus getProcessingIdentityStatus(
            Optional<OrchIdentityCredentials> identityCredentialsOpt, int attempts) {
        return ProcessingIdentityStatus.valueOf(getStatus(identityCredentialsOpt, attempts));
    }

    public static IdentityProgressStatus getIdentityProgressStatus(
            Optional<OrchIdentityCredentials> identityCredentialsOpt, int attempts) {
        return IdentityProgressStatus.valueOf(getStatus(identityCredentialsOpt, attempts));
    }

    private static String getStatus(
            Optional<OrchIdentityCredentials> identityCredentialsOpt, int attempts) {
        if (identityCredentialsOpt.isEmpty() && attempts == 1) {
            return "NO_ENTRY";
        } else if (identityCredentialsOpt.isEmpty()) {
            return "ERROR";
        } else if (Objects.nonNull(identityCredentialsOpt.get().getCoreIdentityJWT())) {
            return "COMPLETED";
        }
        return "PROCESSING";
    }
}
