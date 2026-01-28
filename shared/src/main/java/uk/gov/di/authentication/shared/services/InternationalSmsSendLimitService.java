package uk.gov.di.authentication.shared.services;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.authentication.shared.entity.InternationalSmsSendCount;
import uk.gov.di.authentication.shared.helpers.PhoneNumberHelper;

import java.util.Optional;

public class InternationalSmsSendLimitService extends BaseDynamoService<InternationalSmsSendCount> {

    private static final Logger LOG = LogManager.getLogger(InternationalSmsSendLimitService.class);
    private final ConfigurationService configurationService;

    public InternationalSmsSendLimitService(ConfigurationService configurationService) {
        super(
                InternationalSmsSendCount.class,
                "international-sms-send-count",
                configurationService);
        this.configurationService = configurationService;
    }

    protected InternationalSmsSendLimitService(
            DynamoDbClient client,
            DynamoDbTable<InternationalSmsSendCount> dynamoTable,
            ConfigurationService configurationService) {
        super(dynamoTable, client);
        this.configurationService = configurationService;
    }

    public boolean canSendSms(String phoneNumber) {
        String formattedPhoneNumber = PhoneNumberHelper.formatPhoneNumber(phoneNumber);

        if (PhoneNumberHelper.isDomesticPhoneNumber(formattedPhoneNumber)) {
            return true;
        }

        int sentCount = getSentCount(formattedPhoneNumber);

        return !hasReachedSendLimit(sentCount);
    }

    public void recordSmsSent(String phoneNumber) {
        String formattedPhoneNumber = PhoneNumberHelper.formatPhoneNumber(phoneNumber);

        if (PhoneNumberHelper.isDomesticPhoneNumber(formattedPhoneNumber)) {
            return;
        }

        incrementSentCount(formattedPhoneNumber);
    }

    private boolean hasReachedSendLimit(int sentCount) {
        int limit = configurationService.getInternationalSmsNumberSendLimit();
        boolean hasReached = sentCount >= limit;

        LOG.log(
                hasReached ? Level.WARN : Level.INFO,
                "User {} international SMS send limit - request {}. sentCount={}, limit={}, hasReached={}.",
                hasReached ? "has reached" : "is under the",
                hasReached ? "blocked" : "allowed",
                sentCount,
                limit,
                hasReached);

        return hasReached;
    }

    private void incrementSentCount(String formattedPhoneNumber) {
        Optional<InternationalSmsSendCount> existingRecord = get(formattedPhoneNumber);

        int newSentCount;
        if (existingRecord.isPresent()) {
            newSentCount = existingRecord.get().getSentCount() + 1;
            existingRecord.get().setSentCount(newSentCount);
            update(existingRecord.get());
        } else {
            newSentCount = 1;
            put(
                    new InternationalSmsSendCount()
                            .withPhoneNumber(formattedPhoneNumber)
                            .withSentCount(newSentCount));
        }

        LOG.info("International SMS sent count incremented to {} for phone number.", newSentCount);
    }

    private int getSentCount(String formattedPhoneNumber) {
        Optional<InternationalSmsSendCount> record = get(formattedPhoneNumber);

        if (record.isEmpty()) {
            LOG.info("No count found for phone number, defaulting to 0.");
            return 0;
        }

        return record.get().getSentCount();
    }
}
