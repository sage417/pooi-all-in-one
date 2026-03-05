package app.pooi.workflow.application.service.enums;

public enum TaskAutoCompleteType {
    // 不需要自动审批
    NOT_SATISFY_AUTO_APPROVAL_COND,
    // 当前审批人和流程发起人相同
    CURRENT_APPROVER_IS_INITIATOR,
    // 当前审批人和前一个任务审批人相同且审批通过
    CURRENT_APPROVER_HAS_APPROVED_IN_PREVIOUS_TASK,
    // 当前审批人在当前流程之前任务已经审批通过
    CURRENT_APPROVER_HAS_APPROVED_BEFORE;

}
