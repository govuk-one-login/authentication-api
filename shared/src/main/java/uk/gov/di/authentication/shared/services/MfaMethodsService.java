package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.entity.MfaMethodCreateRequest;
import uk.gov.di.authentication.shared.entity.MfaMethodData;
import uk.gov.di.authentication.shared.exceptions.InvalidPriorityIdentifierException;

import java.util.List;

public interface MfaMethodsService {
    List<MfaMethodData> getMfaMethods(String email);

    MfaMethodData addBackupMfa(String email, MfaMethodCreateRequest.MfaMethod MfaMethod)
            throws InvalidPriorityIdentifierException;
}
