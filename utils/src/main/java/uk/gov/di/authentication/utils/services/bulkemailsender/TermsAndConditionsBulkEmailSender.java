package uk.gov.di.authentication.utils.services.bulkemailsender;

import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;

public class TermsAndConditionsBulkEmailSender extends BaseBulkEmailSender {

    private final List<String> includedTermsAndConditions;

    public TermsAndConditionsBulkEmailSender(
            BulkEmailUsersService bulkEmailUsersService,
            CloudwatchMetricsService cloudwatchMetricsService,
            ConfigurationService configurationService) {
        super(bulkEmailUsersService, cloudwatchMetricsService, configurationService);
        this.includedTermsAndConditions =
                configurationService.getBulkUserEmailIncludedTermsAndConditions();
    }

    @Override
    public boolean validateUser(UserProfile userProfile) {
        var valid =
                userProfile.getTermsAndConditions() == null
                        || includedTermsAndConditions.contains(
                                userProfile.getTermsAndConditions().getVersion());
        if (!valid) {
            updateBulkUserStatus(
                    userProfile.getSubjectID(), BulkEmailStatus.TERMS_ACCEPTED_RECENTLY);
        }
        return valid;
    }
}
