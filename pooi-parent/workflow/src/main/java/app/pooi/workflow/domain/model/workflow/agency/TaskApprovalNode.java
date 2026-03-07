package app.pooi.workflow.domain.model.workflow.agency;

import app.pooi.workflow.domain.model.enums.TaskAgencyType;
import app.pooi.workflow.util.TravelNode;
import jakarta.annotation.Nonnull;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
public class TaskApprovalNode extends TravelNode<TaskApprovalNode> {

    public static final String APPROVAL_ROOT_VALUE = "__APPROVAL__";

    private final TaskAgencyType taskAgencyType;

    private List<TaskDelegatePath> delegatePaths = new ArrayList<>(0);

    public TaskApprovalNode(String value) {
        this(value, TaskAgencyType.NONE);
    }

    private TaskApprovalNode(String value, @Nonnull TaskAgencyType taskAgencyType) {
        super(value);
        this.taskAgencyType = taskAgencyType;
    }

    public static TaskApprovalNode root() {
        return new TaskApprovalNode(APPROVAL_ROOT_VALUE);
    }

    public static TaskApprovalNode fromDelegateNodePath(List<TaskDelegateNode> leafNodePath) {
        TaskApprovalNode taskApprovalNode = new TaskApprovalNode(leafNodePath.getLast().getValue(), TaskAgencyType.DELEGATE);
        taskApprovalNode.getDelegatePaths().add(new TaskDelegatePath(leafNodePath));
        return taskApprovalNode;
    }


}
