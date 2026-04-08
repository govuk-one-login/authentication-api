package uk.gov.di.authentication.utils.entity;

import com.google.gson.annotations.Expose;

import java.util.Map;

public record MFAMethodAnalysisResponse(
        @Expose long countOfAuthAppUsersAssessed,
        @Expose long countOfPhoneNumberUsersAssessed,
        @Expose long countOfUsersWithAuthAppEnabledButNoVerifiedSMSOrAuthAppMFAMethods,
        @Expose long countOfUsersWithVerifiedPhoneNumber,
        @Expose Map<String, Long> phoneDestinationCounts,
        @Expose Map<?, Long> attributeCombinationsForAuthAppUsersCount,
        @Expose long countOfAccountsWithoutAnyMfaMethods,
        @Expose long countOfUsersWithMfaMethodsMigrated,
        @Expose long countOfUsersWithoutMfaMethodsMigrated,
        @Expose long missingUserProfileCount,
        @Expose Map<?, Long> mfaMethodPriorityIdentifierCombinations,
        @Expose Map<String, Long> mfaMethodDetailsCombinations) {}
