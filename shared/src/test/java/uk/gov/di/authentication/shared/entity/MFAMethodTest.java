package uk.gov.di.authentication.shared.entity;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.shared.entity.MFAMethodType.SMS;

class MFAMethodTest {
    @Test
    void convertsAnMfaMethodToAttributeValue() {
        var type = SMS.getValue();
        var timestamp = NowHelper.toTimestampString(NowHelper.now());
        var priority = PriorityIdentifier.BACKUP;
        var identifier = 1;
        var phone = "+4412345678";
        var mfaMethod = new MFAMethod(type, true, true, phone, timestamp, priority, identifier);

        var attributeValue = mfaMethod.toAttributeValue();
        assertEquals(phone, attributeValue.m().get("Destination").s());
        assertEquals(type, attributeValue.m().get("MfaMethodType").s());
        assertEquals(timestamp, attributeValue.m().get("Updated").s());
        assertEquals(priority.name(), attributeValue.m().get("PriorityIdentifier").s());
        assertEquals("1", attributeValue.m().get("Enabled").n());
        assertEquals("1", attributeValue.m().get("MethodVerified").n());
    }
}
