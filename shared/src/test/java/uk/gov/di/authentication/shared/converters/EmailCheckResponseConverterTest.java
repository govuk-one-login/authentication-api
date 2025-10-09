package uk.gov.di.authentication.shared.converters;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.shared.entity.EmailCheckResponse;
import uk.gov.di.authentication.shared.helpers.CommonTestVariables;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class EmailCheckResponseConverterTest {

    private EmailCheckResponseConverter emailCheckResponseConverter;

    @BeforeEach
    public void setUp() {
        emailCheckResponseConverter = new EmailCheckResponseConverter();
    }

    @Test
    void shouldTransformFromEmailCheckResponseToAttributeValue() {
        EmailCheckResponse input = CommonTestVariables.TEST_EMAIL_CHECK_RESPONSE;

        AttributeValue result = emailCheckResponseConverter.transformFrom(input);

        String jsonString = result.s();
        assertTrue(jsonString.contains("\"domain_name\":\"digital.cabinet-office.gov.uk\""));
        assertTrue(
                jsonString.contains(
                        "\"emailFraudCheckResponse\":{\"type\":\"EMAIL_FRAUD_CHECK\"}"));
    }

    @Test
    void shouldTransformToObjectFromAttributeValue() {
        AttributeValue attributeValue =
                AttributeValue.builder()
                        .s(
                                "{\"restricted\":{\"domain_name\":\"digital.cabinet-office.gov.uk\"},\"extensions\":{\"emailFraudCheckResponse\":{\"type\":\"EMAIL_FRAUD_CHECK\"}}}")
                        .build();

        Object result = emailCheckResponseConverter.transformTo(attributeValue);

        assertTrue(result instanceof EmailCheckResponse);
        assertEquals(CommonTestVariables.TEST_EMAIL_CHECK_RESPONSE, result);
    }
}
