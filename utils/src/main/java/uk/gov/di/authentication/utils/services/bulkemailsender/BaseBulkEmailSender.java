package uk.gov.di.authentication.utils.services.bulkemailsender;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Map;

public abstract class BaseBulkEmailSender implements BulkEmailSender {

    private static final Logger LOG = LogManager.getLogger(BaseBulkEmailSender.class);

    protected final BulkEmailUsersService bulkEmailUsersService;
    protected final CloudwatchMetricsService cloudwatchMetricsService;
    protected final ConfigurationService configurationService;

    protected BaseBulkEmailSender(
            BulkEmailUsersService bulkEmailUsersService,
            CloudwatchMetricsService cloudwatchMetricsService,
            ConfigurationService configurationService) {
        this.bulkEmailUsersService = bulkEmailUsersService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.configurationService = configurationService;
    }

    @Override
    public void updateBulkUserStatus(String subjectId, BulkEmailStatus bulkEmailStatus) {
        if (bulkEmailUsersService.updateUserStatus(subjectId, bulkEmailStatus).isPresent()) {
            LOG.info("Bulk email user status updated to: {}", bulkEmailStatus.getValue());
        } else {
            LOG.warn("Bulk user email status not updated, user not found.");
        }
        cloudwatchMetricsService.incrementCounter(
                "BulkEmailStatus",
                Map.of(
                        "Status",
                        bulkEmailStatus.getValue(),
                        "Environment",
                        configurationService.getEnvironment()));
    }
}
