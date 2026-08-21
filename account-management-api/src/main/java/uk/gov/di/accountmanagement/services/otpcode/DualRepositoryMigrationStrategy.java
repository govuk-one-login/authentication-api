package uk.gov.di.accountmanagement.services.otpcode;

import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;

public class DualRepositoryMigrationStrategy {

    protected final OtpCodeRepositoryService sourceOtpCodeRepositoryService = null;

    protected final OtpCodeRepositoryService targetOtpCodeRepositoryService = null;

    public DualRepositoryMigrationStrategy() {}

    public DualRepositoryMigrationStrategy(
            RedisConnectionService redisConnectionService,
            AuthenticationAttemptsService authenticationAttemptsService) {}
}
