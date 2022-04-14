package uk.gov.di.authentication.frontendapi.services;

import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;

public class ResetPasswordService {

    private ConfigurationService configurationService;

    public ResetPasswordService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public String buildResetPasswordLink(
            String code, String sessionID, String persistentSessionId) {
        LocalDateTime localDateTime =
                LocalDateTime.now().plus(configurationService.getCodeExpiry(), ChronoUnit.SECONDS);
        Date expiryDate = Date.from(localDateTime.atZone(ZoneId.of("UTC")).toInstant());
        return buildURI(
                        configurationService.getFrontendBaseUrl(),
                        configurationService.getResetPasswordRoute()
                                + code
                                + "."
                                + expiryDate.toInstant().toEpochMilli()
                                + "."
                                + sessionID
                                + "."
                                + persistentSessionId)
                .toString();
    }
}
