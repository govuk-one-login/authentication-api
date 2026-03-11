package uk.gov.di.authentication.utils.services.bulkemailsender;

import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

public class TermsAndConditionsBulkEmailSender extends BaseBulkEmailSender {

    public TermsAndConditionsBulkEmailSender(
            BulkEmailUsersService bulkEmailUsersService,
            CloudwatchMetricsService cloudwatchMetricsService,
            ConfigurationService configurationService) {
        super(bulkEmailUsersService, cloudwatchMetricsService, configurationService);
    }
}
