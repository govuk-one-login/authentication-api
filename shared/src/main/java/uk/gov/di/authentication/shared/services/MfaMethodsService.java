package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.MfaData;

import java.util.List;

public interface MfaMethodsService {
    List<MfaData> getMfaMethods(String internalCommonSubjectId);
}
