package uk.gov.di.authentication.ipv.utils;

import uk.gov.di.authentication.ipv.entity.ProcessingIdentityStatus;
import uk.gov.di.orchestration.shared.entity.OrchIdentityCredentials;

import java.util.Objects;
import java.util.Optional;

public class IdentityProgressUtils {
    private IdentityProgressUtils() {}

    public static ProcessingIdentityStatus getProcessingIdentityStatus(
            Optional<OrchIdentityCredentials> identityCredentialsOpt, int attempts) {
        if (identityCredentialsOpt.isEmpty() && attempts == 1) {
            return ProcessingIdentityStatus.NO_ENTRY;
        } else if (identityCredentialsOpt.isEmpty()) {
            return ProcessingIdentityStatus.ERROR;
        } else if (Objects.nonNull(identityCredentialsOpt.get().getCoreIdentityJWT())) {
            return ProcessingIdentityStatus.COMPLETED;
        }
        return ProcessingIdentityStatus.PROCESSING;
    }
}
