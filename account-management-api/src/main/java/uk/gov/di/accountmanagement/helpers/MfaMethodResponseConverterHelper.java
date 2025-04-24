package uk.gov.di.accountmanagement.helpers;

import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.response.MfaMethodResponse;

import java.util.List;

import static java.lang.String.format;

public class MfaMethodResponseConverterHelper {
    private MfaMethodResponseConverterHelper() {
        throw new IllegalStateException("Utility class");
    }

    public static Result<String, List<MfaMethodResponse>> convertMfaMethodsToMfaMethodResponse(
            List<MFAMethod> mfaMethods) {
        List<Result<String, MfaMethodResponse>> mfaMethodDataResults =
                mfaMethods.stream()
                        .map(
                                mfaMethod -> {
                                    var mfaMethodData = MfaMethodResponse.from(mfaMethod);
                                    return mfaMethodData.mapFailure(
                                            failure ->
                                                    format(
                                                            "Error converting mfa method to mfa method data: %s",
                                                            mfaMethodData.getFailure()));
                                })
                        .toList();
        return Result.sequenceSuccess(mfaMethodDataResults);
    }
}
