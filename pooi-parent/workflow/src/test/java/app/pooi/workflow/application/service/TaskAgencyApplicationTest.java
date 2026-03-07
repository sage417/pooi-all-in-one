package app.pooi.workflow.application.service;

import app.pooi.workflow.domain.model.workflow.agency.TaskApprovalNode;
import app.pooi.workflow.domain.model.workflow.agency.TaskDelegateNode;
import app.pooi.workflow.util.TravelNode;
import com.google.common.collect.Lists;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

class TaskAgencyApplicationTest {

    @Test
    public void delegateSingle() {

        TaskApprovalNode taskApprovalNode = TaskApprovalNode.root();
        taskApprovalNode.addChild(new TaskApprovalNode("A"));
        taskApprovalNode.addChild(new TaskApprovalNode("B"));
        taskApprovalNode.addChild(new TaskApprovalNode("C"));

        TaskDelegateNode taskDelegateNode = TaskDelegateNode.root();
        TaskDelegateNode delegateNodeA = new TaskDelegateNode("A");
        delegateNodeA.addChild(new TaskDelegateNode("E"));
        taskDelegateNode.addChild(delegateNodeA);

        TaskApprovalNode approvalNode = UserTaskAgencyAppService.calculateApprovalDelegateRelation(taskApprovalNode, taskDelegateNode);

        Assertions.assertThat(approvalNode.getChildren()).hasSize(3);
        Assertions.assertThat(approvalNode.getChildren().stream().map(TravelNode::getValue).toList())
                .containsAll(Lists.newArrayList("E", "B", "C"));

        for (TaskApprovalNode child : approvalNode.getChildren()) {
            if (child.getValue().equals("E")) {
                Assertions.assertThat(child.getDelegatePaths()).hasSize(1);
                Assertions.assertThat(child.getDelegatePaths().getFirst().getDelegateChains()).hasSize(2);
                break;
            }
        }
    }

    @Test
    public void delegateMany() {

        TaskApprovalNode taskApprovalNode = TaskApprovalNode.root();
        taskApprovalNode.addChild(new TaskApprovalNode("A"));
        taskApprovalNode.addChild(new TaskApprovalNode("B"));
        taskApprovalNode.addChild(new TaskApprovalNode("C"));

        TaskDelegateNode taskDelegateNode = TaskDelegateNode.root();
        TaskDelegateNode delegateNodeA = new TaskDelegateNode("A");
        delegateNodeA.addChild(new TaskDelegateNode("E"));
        delegateNodeA.addChild(new TaskDelegateNode("F"));
        taskDelegateNode.addChild(delegateNodeA);

        TaskApprovalNode approvalNode = UserTaskAgencyAppService.calculateApprovalDelegateRelation(taskApprovalNode, taskDelegateNode);

        Assertions.assertThat(approvalNode.getChildren()).hasSize(4);
        Assertions.assertThat(approvalNode.getChildren().stream().map(TravelNode::getValue).toList())
                .containsAll(Lists.newArrayList("E", "F", "B", "C"));
    }

    @Test
    public void passthrough() {

        TaskApprovalNode taskApprovalNode = TaskApprovalNode.root();
        taskApprovalNode.addChild(new TaskApprovalNode("A"));
        taskApprovalNode.addChild(new TaskApprovalNode("B"));
        taskApprovalNode.addChild(new TaskApprovalNode("C"));

        TaskDelegateNode taskDelegateNode = TaskDelegateNode.root();
        TaskDelegateNode delegateNodeB = new TaskDelegateNode("B");
        TaskDelegateNode delegateNodeC = new TaskDelegateNode("C");

        delegateNodeB.addChild(delegateNodeC);
        taskDelegateNode.addChild(delegateNodeB);
        delegateNodeC.addChild(new TaskDelegateNode("D"));

        TaskApprovalNode approvalNode = UserTaskAgencyAppService.calculateApprovalDelegateRelation(taskApprovalNode, taskDelegateNode);

        Assertions.assertThat(approvalNode.getChildren()).hasSize(3);
        Assertions.assertThat(approvalNode.getChildren().stream().map(TravelNode::getValue).toList())
                .containsAll(Lists.newArrayList("A", "D", "C"));

    }


    // delegate more than one
    @Test
    public void calculateApprovalDelegateRelation() {
        TaskApprovalNode taskApprovalNode = TaskApprovalNode.root();
        taskApprovalNode.addChild(new TaskApprovalNode("A"));
        taskApprovalNode.addChild(new TaskApprovalNode("B"));
        taskApprovalNode.addChild(new TaskApprovalNode("C"));

        TaskDelegateNode taskDelegateNode = TaskDelegateNode.root();
        TaskDelegateNode delegateNodeA = new TaskDelegateNode("A");
        delegateNodeA.addChild(new TaskDelegateNode("E"));
        delegateNodeA.addChild(new TaskDelegateNode("F"));
        taskDelegateNode.addChild(delegateNodeA);
        TaskDelegateNode delegateNodeB = new TaskDelegateNode("B");
        TaskDelegateNode delegateNodeC = new TaskDelegateNode("C");
        delegateNodeB.addChild(delegateNodeC);
        taskDelegateNode.addChild(delegateNodeB);
        delegateNodeC.addChild(new TaskDelegateNode("D"));
        taskDelegateNode.addChild(delegateNodeC);

        TaskApprovalNode approvalNode = UserTaskAgencyAppService.calculateApprovalDelegateRelation(taskApprovalNode, taskDelegateNode);
        // D E F
        Assertions.assertThat(approvalNode.getChildren()).hasSize(3);
        Assertions.assertThat(approvalNode.getChildren().stream().map(TravelNode::getValue).toList())
                .containsAll(Lists.newArrayList("D", "E", "F"));
    }
}