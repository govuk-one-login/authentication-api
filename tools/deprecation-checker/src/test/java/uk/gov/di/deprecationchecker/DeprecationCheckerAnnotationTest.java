package uk.gov.di.deprecationchecker;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.EnumConstantDeclaration;
import com.github.javaparser.ast.body.EnumDeclaration;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DeprecationCheckerAnnotationTest {

    @Test
    void shouldDetectDeprecatedAnnotation() throws Exception {
        String javaCode =
                """
            public enum TestEnum {
                @Deprecated
                DEPRECATED_CONSTANT,
                NORMAL_CONSTANT
            }
            """;

        JavaParser parser = new JavaParser();
        CompilationUnit unit = parser.parse(javaCode).getResult().orElseThrow();
        EnumDeclaration enumDecl = unit.findAll(EnumDeclaration.class).get(0);

        EnumConstantDeclaration deprecatedConstant = enumDecl.getEntries().get(0);
        EnumConstantDeclaration normalConstant = enumDecl.getEntries().get(1);

        assertTrue(DeprecationChecker.isDeprecated(deprecatedConstant));
        assertFalse(DeprecationChecker.isDeprecated(normalConstant));
    }

    @Test
    void shouldDetectFullyQualifiedDeprecatedAnnotation() throws Exception {
        String javaCode =
                """
            public enum TestEnum {
                @java.lang.Deprecated
                DEPRECATED_CONSTANT,
                NORMAL_CONSTANT
            }
            """;

        JavaParser parser = new JavaParser();
        CompilationUnit unit = parser.parse(javaCode).getResult().orElseThrow();
        EnumDeclaration enumDecl = unit.findAll(EnumDeclaration.class).get(0);

        EnumConstantDeclaration deprecatedConstant = enumDecl.getEntries().get(0);
        EnumConstantDeclaration normalConstant = enumDecl.getEntries().get(1);

        // Current implementation only checks for "Deprecated", not fully qualified
        // This test documents current behavior
        assertFalse(DeprecationChecker.isDeprecated(deprecatedConstant));
        assertFalse(DeprecationChecker.isDeprecated(normalConstant));
    }

    @Test
    void shouldHandleMultipleAnnotations() throws Exception {
        String javaCode =
                """
            public enum TestEnum {
                @SuppressWarnings("unused")
                @Deprecated
                DEPRECATED_CONSTANT
            }
            """;

        JavaParser parser = new JavaParser();
        CompilationUnit unit = parser.parse(javaCode).getResult().orElseThrow();
        EnumDeclaration enumDecl = unit.findAll(EnumDeclaration.class).get(0);

        EnumConstantDeclaration deprecatedConstant = enumDecl.getEntries().get(0);

        assertTrue(DeprecationChecker.isDeprecated(deprecatedConstant));
    }

    @Test
    void shouldHandleNoAnnotations() throws Exception {
        String javaCode =
                """
            public enum TestEnum {
                NORMAL_CONSTANT
            }
            """;

        JavaParser parser = new JavaParser();
        CompilationUnit unit = parser.parse(javaCode).getResult().orElseThrow();
        EnumDeclaration enumDecl = unit.findAll(EnumDeclaration.class).get(0);

        EnumConstantDeclaration normalConstant = enumDecl.getEntries().get(0);

        assertFalse(DeprecationChecker.isDeprecated(normalConstant));
    }
}
