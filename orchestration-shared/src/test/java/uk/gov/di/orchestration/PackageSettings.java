package uk.gov.di.orchestration;

import org.approvaltests.core.ApprovalFailureReporter;
import org.approvaltests.reporters.AutoApproveWhenEmptyReporter;
import org.approvaltests.reporters.JunitReporter;

public class PackageSettings {
    public static ApprovalFailureReporter UseReporter =
            new AutoApproveWhenEmptyReporter(new JunitReporter());
    public static ApprovalFailureReporter FrontloadedReporter =
            new AutoApproveWhenEmptyReporter(new JunitReporter());
    public static String UseApprovalSubdirectory = "approvals";
    public static String ApprovalBaseDirectory = "../resources";
}
