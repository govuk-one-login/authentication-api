package uk.gov.di.accountmanagement.entity;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IADCircuitBreakerItemTest {

    @Test
    void shouldRoundTripAllFields() {
        var item = new IADCircuitBreakerItem();
        item.setPk("IAD");
        item.setDatetime(1783408027000L);
        item.setEnabled(true);
        item.setMetadataJson("{\"guardrailType\":\"AuthUserActivityCheck\"}");

        assertEquals("IAD", item.getPk());
        assertEquals(1783408027000L, item.getDatetime());
        assertTrue(item.isEnabled());
        assertEquals("{\"guardrailType\":\"AuthUserActivityCheck\"}", item.getMetadataJson());
    }

    @Test
    void shouldDefaultEnabledToFalse() {
        var item = new IADCircuitBreakerItem();

        assertFalse(item.isEnabled());
    }

    @Test
    void shouldDefaultMetadataJsonToNull() {
        var item = new IADCircuitBreakerItem();

        assertNull(item.getMetadataJson());
    }

    @Test
    void shouldHaveCorrectPartitionKeyConstant() {
        assertEquals("IAD", IADCircuitBreakerItem.PARTITION_KEY);
    }
}
