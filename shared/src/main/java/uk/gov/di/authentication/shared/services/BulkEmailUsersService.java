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
    public static final String DELIVERY_RECEIPT_STATUS_FIELD = "DeliveryReceiptStatus";
    public static final String DELIVERY_RECEIPT_STATUS_INDEX = "DeliveryReceiptStatusIndex";
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

    public Optional<BulkEmailUser> updateDeliveryReceiptStatus(
            String subjectID, String deliveryReceiptStatus) {
        return getBulkEmailUsers(subjectID)
                .map(
                        user -> {
                            user.withDeliveryReceiptStatus(deliveryReceiptStatus);
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
        QueryRequest queryRequest =
                QueryRequest.builder()
                        .tableName(
                                configurationService.getEnvironment()
                                        + "-"
                                        + BULK_EMAIL_USERS_TABLE)
                        .keyConditions(
                                Map.of(
                                        BULK_EMAIL_STATUS_FIELD,
                                        equalityCondition(bulkEmailStatus.toString())))
                        .indexName(BULK_EMAIL_STATUS_INDEX)
                        .limit(limit)
                        .build();

        return getSubjectIdsFromQueryRequest(queryRequest);
    }

    public List<String> getNSubjectIdsByDeliveryReceiptStatus(
            Integer limit, String deliveryReceiptStatus) {
        QueryRequest queryRequest =
                QueryRequest.builder()
                        .tableName(
                                configurationService.getEnvironment()
                                        + "-"
                                        + BULK_EMAIL_USERS_TABLE)
                        .keyConditions(
                                Map.of(
                                        DELIVERY_RECEIPT_STATUS_FIELD,
                                        equalityCondition(deliveryReceiptStatus)))
                        .filterExpression("BulkEmailStatus = :status")
                        .expressionAttributeValues(
                                Map.of(
                                        ":status",
                                        AttributeValue.fromS(
                                                BulkEmailStatus.EMAIL_SENT.toString())))
                        .indexName(DELIVERY_RECEIPT_STATUS_INDEX)
                        .limit(limit)
                        .build();

        return getSubjectIdsFromQueryRequest(queryRequest);
    }

    private List<String> getSubjectIdsFromQueryRequest(QueryRequest queryRequest) {
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

    private Condition equalityCondition(String equalTo) {
        return Condition.builder()
                .comparisonOperator(ComparisonOperator.EQ)
                .attributeValueList(AttributeValue.builder().s(equalTo).build())
                .build();
    }
}
