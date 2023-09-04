package uk.gov.di.authentication.shared.services;

import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ComparisonOperator;
import software.amazon.awssdk.services.dynamodb.model.Condition;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.entity.BulkEmailUser;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

public class BulkEmailUsersService extends BaseDynamoService<BulkEmailUser> {

    private final ConfigurationService configurationService;

    private static final String BULK_EMAIL_USERS_TABLE = "bulk-email-users";
    private static final String BULK_EMAIL_STATUS_INDEX = "BulkEmailStatusIndex";
    private static final String BULK_EMAIL_STATUS_FIELD = "BulkEmailStatus";
    private static final String SUBJECT_ID_FIELD = "SubjectID";

    public BulkEmailUsersService(ConfigurationService configurationService) {
        super(BulkEmailUser.class, BULK_EMAIL_USERS_TABLE, configurationService);
        this.configurationService = configurationService;
    }

    public Optional<BulkEmailUser> getBulkEmailUsers(String subjectID) {
        return get(subjectID);
    }

    public Optional<BulkEmailUser> updateUserStatus(
            String subjectID, BulkEmailStatus bulkEmailStatus) {
        return getBulkEmailUsers(subjectID)
                .map(
                        user -> {
                            LocalDateTime now = LocalDateTime.now(configurationService.getClock());
                            user.withBulkEmailStatus(bulkEmailStatus).withUpdatedAt(now.toString());
                            update(user);
                            return user;
                        });
    }

    public void addUser(String subjectID, BulkEmailStatus bulkEmailStatus) {
        LocalDateTime now = LocalDateTime.now(configurationService.getClock());
        put(
                new BulkEmailUser()
                        .withSubjectID(subjectID)
                        .withBulkEmailStatus(bulkEmailStatus)
                        .withCreatedAt(now.toString()));
    }

    public List<String> getNSubjectIdsByStatus(Integer limit, BulkEmailStatus bulkEmailStatus) {
        Condition equalsBulkEmailStatus =
                Condition.builder()
                        .comparisonOperator(ComparisonOperator.EQ)
                        .attributeValueList(
                                AttributeValue.builder().s(bulkEmailStatus.toString()).build())
                        .build();

        QueryRequest queryRequest =
                QueryRequest.builder()
                        .tableName(
                                configurationService.getEnvironment()
                                        + "-"
                                        + BULK_EMAIL_USERS_TABLE)
                        .keyConditions(Map.of(BULK_EMAIL_STATUS_FIELD, equalsBulkEmailStatus))
                        .indexName(BULK_EMAIL_STATUS_INDEX)
                        .limit(limit)
                        .build();

        var queryItems = query(queryRequest).items().stream();

        return queryItems
                .flatMap(
                        item ->
                                item
                                        .get(SUBJECT_ID_FIELD)
                                        .getValueForField("S", String.class)
                                        .stream())
                .collect(Collectors.toList());
    }
}
