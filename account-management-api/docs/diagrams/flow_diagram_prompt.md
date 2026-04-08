# Flow Diagram Creation Prompt

Use this prompt to create flow diagrams for handler classes following the standards in `audit_flow_diagram_rules.md`:

```
Create a flow diagram for the [HandlerClassName] class following the audit_flow_diagram_rules.md standards.

Save the diagram as [handler_name]_flow.md in the account-management-api/docs/diagrams/ directory.
```

## Example Usage

```
Create a flow diagram for the MFAMethodsPutHandler class following the audit_flow_diagram_rules.md standards.

Save the diagram as mfa_method_update_flow.md in the account-management-api/docs/diagrams/ directory.
```

This prompt is intentionally minimal as all requirements for diagram content, styling, and verification are already specified in the Rules file.