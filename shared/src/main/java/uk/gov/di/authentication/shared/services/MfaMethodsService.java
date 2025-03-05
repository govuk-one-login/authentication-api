package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.MfaMethodData;

import java.util.List;

public interface MfaMethodsService {
    List<MfaMethodData> getMfaMethods(String email);
}
