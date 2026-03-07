package app.pooi.workflow.domain.model.workflow.agency;

import app.pooi.workflow.util.TravelNode;


public class TaskDelegateNode extends TravelNode<TaskDelegateNode> {

    public TaskDelegateNode(String value) {
        super(value);
    }

    public static TaskDelegateNode root() {
        return new TaskDelegateNode("__DELEGATE__");
    }
}
