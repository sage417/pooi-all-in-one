/*
 * Copyright (c) 2024. Lorem ipsum dolor sit amet, consectetur adipiscing elit.
 * Morbi non lorem porttitor neque feugiat blandit. Ut vitae ipsum eget quam lacinia accumsan.
 * Etiam sed turpis ac ipsum condimentum fringilla. Maecenas magna.
 * Proin dapibus sapien vel ante. Aliquam erat volutpat. Pellentesque sagittis ligula eget metus.
 * Vestibulum commodo. Ut rhoncus gravida arcu.
 */

package app.pooi.workflow.infrastructure.configuration.flowable.behavior;

import app.pooi.workflow.application.service.UserTaskAgencyAppService;
import app.pooi.workflow.application.service.UserTaskAutoCompleteAppService;
import app.pooi.workflow.application.service.enums.TaskAutoCompleteType;
import app.pooi.workflow.domain.model.workflow.agency.TaskDelegateResult;
import app.pooi.workflow.domain.model.workflow.comment.Comment;
import app.pooi.workflow.domain.service.comment.CommentService;
import app.pooi.workflow.infrastructure.configuration.flowable.props.FlowableCustomProperties;
import app.pooi.workflow.util.TaskEntityUtil;
import app.pooi.workflow.util.TravelNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.Sets;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.flowable.bpmn.model.UserTask;
import org.flowable.common.engine.api.delegate.Expression;
import org.flowable.common.engine.api.delegate.event.FlowableEngineEventType;
import org.flowable.common.engine.api.delegate.event.FlowableEventDispatcher;
import org.flowable.common.engine.impl.el.ExpressionManager;
import org.flowable.common.engine.impl.interceptor.CommandContext;
import org.flowable.common.engine.impl.logging.LoggingSessionConstants;
import org.flowable.engine.DynamicBpmnConstants;
import org.flowable.engine.delegate.BpmnError;
import org.flowable.engine.delegate.DelegateExecution;
import org.flowable.engine.delegate.TaskListener;
import org.flowable.engine.impl.bpmn.behavior.UserTaskActivityBehavior;
import org.flowable.engine.impl.bpmn.helper.DynamicPropertyUtil;
import org.flowable.engine.impl.bpmn.helper.ErrorPropagation;
import org.flowable.engine.impl.bpmn.helper.SkipExpressionUtil;
import org.flowable.engine.impl.cfg.ProcessEngineConfigurationImpl;
import org.flowable.engine.impl.context.BpmnOverrideContext;
import org.flowable.engine.impl.persistence.entity.ExecutionEntity;
import org.flowable.engine.impl.util.BpmnLoggingSessionUtil;
import org.flowable.engine.impl.util.CommandContextUtil;
import org.flowable.engine.impl.util.IdentityLinkUtil;
import org.flowable.engine.impl.util.TaskHelper;
import org.flowable.engine.interceptor.CreateUserTaskAfterContext;
import org.flowable.engine.interceptor.CreateUserTaskBeforeContext;
import org.flowable.engine.interceptor.MigrationContext;
import org.flowable.identitylink.api.IdentityLinkType;
import org.flowable.identitylink.service.IdentityLinkService;
import org.flowable.identitylink.service.impl.persistence.entity.IdentityLinkEntity;
import org.flowable.task.service.TaskService;
import org.flowable.task.service.event.impl.FlowableTaskEventBuilder;
import org.flowable.task.service.impl.persistence.entity.TaskEntity;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
public class CustomUserTaskActivityBehavior extends UserTaskActivityBehavior {

    private final FlowableCustomProperties flowableCustomProperties;

    private final UserTaskAgencyAppService taskAgencyAppService;

    private final CommentService commentService;

    private final UserTaskAutoCompleteAppService userTaskAutoCompleteAppService;

    public CustomUserTaskActivityBehavior(UserTask userTask,
                                          FlowableCustomProperties flowableCustomProperties,
                                          UserTaskAgencyAppService taskAgencyAppService,
                                          UserTaskAutoCompleteAppService userTaskAutoCompleteAppService, CommentService commentService
    ) {
        super(userTask);
        this.flowableCustomProperties = flowableCustomProperties;
        this.taskAgencyAppService = taskAgencyAppService;
        this.userTaskAutoCompleteAppService = userTaskAutoCompleteAppService;
        this.commentService = commentService;
    }

    @Override
    public void execute(DelegateExecution execution, MigrationContext migrationContext) {
        CommandContext commandContext = CommandContextUtil.getCommandContext();
        ProcessEngineConfigurationImpl processEngineConfiguration = CommandContextUtil.getProcessEngineConfiguration();
        TaskService taskService = processEngineConfiguration.getTaskServiceConfiguration().getTaskService();

        TaskEntity task = taskService.createTask();
        task.setExecutionId(execution.getId());
        task.setTaskDefinitionKey(userTask.getId());
        task.setPropagatedStageInstanceId(execution.getPropagatedStageInstanceId());

        String activeTaskName = null;
        String activeTaskDescription = null;
        String activeTaskDueDate = null;
        String activeTaskPriority = null;
        String activeTaskCategory = null;
        String activeTaskFormKey = null;
        String activeTaskSkipExpression = null;
        String activeTaskAssignee = null;
        String activeTaskOwner = null;
        String activeTaskIdVariableName = null;
        List<String> activeTaskCandidateUsers = null;
        List<String> activeTaskCandidateGroups = null;

        ExpressionManager expressionManager = processEngineConfiguration.getExpressionManager();

        if (processEngineConfiguration.isEnableProcessDefinitionInfoCache()) {
            ObjectNode taskElementProperties = BpmnOverrideContext.getBpmnOverrideElementProperties(userTask.getId(), execution.getProcessDefinitionId());
            activeTaskName = DynamicPropertyUtil.getActiveValue(userTask.getName(), DynamicBpmnConstants.USER_TASK_NAME, taskElementProperties);
            activeTaskDescription = DynamicPropertyUtil.getActiveValue(userTask.getDocumentation(), DynamicBpmnConstants.USER_TASK_DESCRIPTION, taskElementProperties);
            activeTaskDueDate = DynamicPropertyUtil.getActiveValue(userTask.getDueDate(), DynamicBpmnConstants.USER_TASK_DUEDATE, taskElementProperties);
            activeTaskPriority = DynamicPropertyUtil.getActiveValue(userTask.getPriority(), DynamicBpmnConstants.USER_TASK_PRIORITY, taskElementProperties);
            activeTaskCategory = DynamicPropertyUtil.getActiveValue(userTask.getCategory(), DynamicBpmnConstants.USER_TASK_CATEGORY, taskElementProperties);
            activeTaskFormKey = DynamicPropertyUtil.getActiveValue(userTask.getFormKey(), DynamicBpmnConstants.USER_TASK_FORM_KEY, taskElementProperties);
            activeTaskSkipExpression = DynamicPropertyUtil.getActiveValue(userTask.getSkipExpression(), DynamicBpmnConstants.TASK_SKIP_EXPRESSION, taskElementProperties);
            activeTaskAssignee = getAssigneeValue(userTask, migrationContext, taskElementProperties);
            activeTaskOwner = getOwnerValue(userTask, migrationContext, taskElementProperties);
            activeTaskCandidateUsers = getActiveValueList(userTask.getCandidateUsers(), DynamicBpmnConstants.USER_TASK_CANDIDATE_USERS, taskElementProperties);
            activeTaskCandidateGroups = getActiveValueList(userTask.getCandidateGroups(), DynamicBpmnConstants.USER_TASK_CANDIDATE_GROUPS, taskElementProperties);
            activeTaskIdVariableName = DynamicPropertyUtil.getActiveValue(userTask.getTaskIdVariableName(), DynamicBpmnConstants.USER_TASK_TASK_ID_VARIABLE_NAME, taskElementProperties);
        } else {
            activeTaskName = userTask.getName();
            activeTaskDescription = userTask.getDocumentation();
            activeTaskDueDate = userTask.getDueDate();
            activeTaskPriority = userTask.getPriority();
            activeTaskCategory = userTask.getCategory();
            activeTaskFormKey = userTask.getFormKey();
            activeTaskSkipExpression = userTask.getSkipExpression();
            activeTaskAssignee = getAssigneeValue(userTask, migrationContext, null);
            activeTaskOwner = getOwnerValue(userTask, migrationContext, null);
            activeTaskCandidateUsers = userTask.getCandidateUsers();
            activeTaskCandidateGroups = userTask.getCandidateGroups();
            activeTaskIdVariableName = userTask.getTaskIdVariableName();
        }

        if (execution.getCurrentActivityName() != null) {
            activeTaskName = execution.getCurrentActivityName();
        }

        CreateUserTaskBeforeContext beforeContext = new CreateUserTaskBeforeContext(userTask, execution, activeTaskName, activeTaskDescription, activeTaskDueDate,
                activeTaskPriority, activeTaskCategory, activeTaskFormKey, activeTaskSkipExpression, activeTaskAssignee, activeTaskOwner,
                activeTaskCandidateUsers, activeTaskCandidateGroups);

        if (processEngineConfiguration.getCreateUserTaskInterceptor() != null) {
            processEngineConfiguration.getCreateUserTaskInterceptor().beforeCreateUserTask(beforeContext);
        }

        handleName(beforeContext, expressionManager, task, execution);
        handleDescription(beforeContext, expressionManager, task, execution);
        handleDueDate(beforeContext, expressionManager, task, execution, processEngineConfiguration, activeTaskDueDate);
        handlePriority(beforeContext, expressionManager, task, execution, activeTaskPriority);
        handleCategory(beforeContext, expressionManager, task, execution);
        handleFormKey(beforeContext, expressionManager, task, execution);

        boolean skipUserTask = SkipExpressionUtil.isSkipExpressionEnabled(beforeContext.getSkipExpression(), userTask.getId(), execution, commandContext)
                && SkipExpressionUtil.shouldSkipFlowElement(beforeContext.getSkipExpression(), userTask.getId(), execution, commandContext);

        TaskHelper.insertTask(task, (ExecutionEntity) execution, !skipUserTask, (!skipUserTask && processEngineConfiguration.isEnableEntityLinks()));

        // Handling assignments need to be done after the task is inserted, to have an id
        if (!skipUserTask) {
            if (processEngineConfiguration.isLoggingSessionEnabled()) {
                BpmnLoggingSessionUtil.addLoggingData(LoggingSessionConstants.TYPE_USER_TASK_CREATE, "User task '" +
                        task.getName() + "' created", task, execution);
            }

            handleAssignments(taskService, beforeContext.getAssignee(), beforeContext.getOwner(), beforeContext.getCandidateUsers(),
                    beforeContext.getCandidateGroups(), task, expressionManager, execution, processEngineConfiguration);

            // ---------- task agency ---------- //
            taskAgencyAfterHandleAssignments((ExecutionEntity) execution, task, processEngineConfiguration);
            // ---------- task agency ---------- //

            if (processEngineConfiguration.getCreateUserTaskInterceptor() != null) {
                CreateUserTaskAfterContext afterContext = new CreateUserTaskAfterContext(userTask, task, execution);
                processEngineConfiguration.getCreateUserTaskInterceptor().afterCreateUserTask(afterContext);
            }

            try {
                processEngineConfiguration.getListenerNotificationHelper().executeTaskListeners(task, TaskListener.EVENTNAME_CREATE);
            } catch (BpmnError bpmnError) {
                ErrorPropagation.propagateError(bpmnError, execution);
                return;
            }

            // All properties set, now firing 'create' events
            FlowableEventDispatcher eventDispatcher = processEngineConfiguration.getTaskServiceConfiguration().getEventDispatcher();
            if (eventDispatcher != null && eventDispatcher.isEnabled()) {
                eventDispatcher.dispatchEvent(FlowableTaskEventBuilder.createEntityEvent(FlowableEngineEventType.TASK_CREATED, task),
                        processEngineConfiguration.getEngineCfgKey());
            }

            if (StringUtils.isNotEmpty(activeTaskIdVariableName)) {
                Expression expression = expressionManager.createExpression(userTask.getTaskIdVariableName());
                String idVariableName = (String) expression.getValue(execution);
                if (StringUtils.isNotEmpty(idVariableName)) {
                    execution.setVariable(idVariableName, task.getId());
                }
            }

            // ---------- auto complete ---------- //
            TaskAutoCompleteType autoCompleteType = userTaskAutoCompleteAppService.satisfyAutoCompleteCond(task, (ExecutionEntity) execution, commandContext);
            if (!TaskAutoCompleteType.NO_AUTO_APPROVAL_NEEDED.equals(autoCompleteType)) {
                TaskHelper.completeTask(task, null, null, null, null, null, commandContext);
                Comment autoCompleteComment = this.commentService.createFromTask(task, "AUTO_COMPLETE");
//                autoCompleteComment.setOperationDetail(autoCompleteType.name());
                this.commentService.cacheComment(autoCompleteComment);
            }
            // ---------- auto complete ---------- //
        } else {
            TaskHelper.deleteTask(task, null, false, false, false); // false: no events fired for skipped user task
            leave(execution);
        }
    }

    private void taskAgencyAfterHandleAssignments(ExecutionEntity execution, TaskEntity task, ProcessEngineConfigurationImpl processEngineConfiguration) {

        TaskDelegateResult delegateResult;
        if (BooleanUtils.isTrue(flowableCustomProperties.getApprovalDelegateEnable())
                && (delegateResult = taskAgencyAppService.matchTaskDelegate(execution, task, true)).isMatchDelegateProfile()) {

            Set<String> assigneeAfterDelegate = delegateResult.getAssigneeAfterDelegate().getChildren().stream()
                    .map(TravelNode::getValue).collect(Collectors.toSet());

            // update task assignee
            String newAssignee = null;
            if (assigneeAfterDelegate.size() == 1) {
                newAssignee = assigneeAfterDelegate.iterator().next();
                assigneeAfterDelegate.remove(newAssignee);
            }
            // task service change assignee
            TaskHelper.changeTaskAssignee(task, newAssignee);

            // update candidates
            for (String userId : Sets.difference(TaskEntityUtil.getCandidates(task), assigneeAfterDelegate)) {
                IdentityLinkUtil.deleteTaskIdentityLinks(task, userId, null, IdentityLinkType.CANDIDATE);
            }

            IdentityLinkService identityLinkService = processEngineConfiguration.getIdentityLinkServiceConfiguration()
                    .getIdentityLinkService();
            List<IdentityLinkEntity> identityLinkEntities = identityLinkService.addCandidateUsers(task.getId(),
                    Sets.difference(assigneeAfterDelegate, TaskEntityUtil.getCandidates(task)));

            if (identityLinkEntities != null && !identityLinkEntities.isEmpty()) {
                IdentityLinkUtil.handleTaskIdentityLinkAdditions(task, identityLinkEntities);
            }
        }
    }
}
