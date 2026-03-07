package app.pooi.workflow.domain.model.workflow.agency;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

@Accessors(chain = true)
@Getter
@Setter
public class TaskDelegateResult {

    public static final TaskDelegateResult NO_NEED_CHANGE_ASSIGNEE_RESULT = new TaskDelegateResult().setMatchDelegateProfile(false);

    private boolean matchDelegateProfile;

    private TaskApprovalNode assigneeAfterDelegate;

}
