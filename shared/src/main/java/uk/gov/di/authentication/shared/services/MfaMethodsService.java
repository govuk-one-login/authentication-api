package uk.gov.di.authentication.shared.services;

import io.vavr.control.Either;
import uk.gov.di.authentication.entity.MfaMethodCreateRequest;
import uk.gov.di.authentication.shared.entity.MfaMethodData;
import uk.gov.di.authentication.shared.exceptions.InvalidPriorityIdentifierException;
import uk.gov.di.authentication.shared.services.mfa.MfaDeleteFailureReason;

import java.util.List;

public interface MfaMethodsService {
    List<MfaMethodData> getMfaMethods(String email);

    MfaMethodData addBackupMfa(String email, MfaMethodCreateRequest.MfaMethod mfaMethod)
            throws InvalidPriorityIdentifierException;

    Either<MfaDeleteFailureReason, String> deleteMfaMethod(
            String email, String mfaMethodIdentifier);
}
