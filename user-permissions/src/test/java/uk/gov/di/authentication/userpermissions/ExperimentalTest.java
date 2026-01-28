package uk.gov.di.authentication.userpermissions;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.userpermissions.entity.PermissionContext;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExperimentalTest {

    @Test
    void shouldHaveCorrectAnnotationAttributes() {
        // Given
        Class<Experimental> annotationClass = Experimental.class;

        // When
        boolean isDocumented =
                annotationClass.isAnnotationPresent(java.lang.annotation.Documented.class);
        java.lang.annotation.Retention retention =
                annotationClass.getAnnotation(java.lang.annotation.Retention.class);
        java.lang.annotation.Target target =
                annotationClass.getAnnotation(java.lang.annotation.Target.class);

        // Then
        assertTrue(isDocumented, "Experimental annotation should be @Documented");
        assertNotNull(retention, "Experimental annotation should have @Retention");
        assertEquals(
                java.lang.annotation.RetentionPolicy.RUNTIME,
                retention.value(),
                "Experimental annotation should have RUNTIME retention policy");
        assertNotNull(target, "Experimental annotation should have @Target");
    }

    @Test
    void shouldBeAppliedToUserPermissionsMethod() throws NoSuchMethodException {
        // Given
        Method canLoginMethod =
                PermissionDecisions.class.getMethod(
                        "canLogin",
                        uk.gov.di.authentication.shared.entity.JourneyType.class,
                        PermissionContext.class);

        // When
        Experimental annotation = canLoginMethod.getAnnotation(Experimental.class);

        // Then
        assertNotNull(annotation, "canLogin method should be annotated with @Experimental");
        assertEquals(
                "Could be an alternative to canReceivePassword",
                annotation.value(),
                "Annotation should have the correct description value");
    }
}
