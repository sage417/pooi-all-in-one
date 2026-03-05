package app.pooi.workflow.application.service;

import app.pooi.workflow.application.service.enums.TaskAutoCompleteType;
import app.pooi.workflow.util.BpmnModelUtil;
import app.pooi.workflow.util.TaskEntityUtil;
import com.google.common.collect.Ordering;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.flowable.bpmn.model.FlowNode;
import org.flowable.bpmn.model.UserTask;
import org.flowable.common.engine.impl.interceptor.CommandContext;
import org.flowable.common.engine.impl.persistence.cache.EntityCache;
import org.flowable.engine.impl.persistence.entity.ExecutionEntity;
import org.flowable.engine.impl.util.CommandContextUtil;
import org.flowable.task.api.TaskInfo;
import org.flowable.task.api.history.HistoricTaskInstance;
import org.flowable.task.service.impl.persistence.entity.HistoricTaskInstanceEntity;
import org.flowable.task.service.impl.persistence.entity.TaskEntity;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Slf4j
@Service
public class UserTaskAutoCompleteAppService {

    public TaskAutoCompleteType satisfyAutoCompleteCond(TaskEntity task, ExecutionEntity execution, CommandContext commandContext) {

        String processDefinitionKey = execution.getProcessDefinitionKey();
        String taskDefinitionKey = task.getTaskDefinitionKey();

        log.info("satisfyAutoCompleteCond {} {}", processDefinitionKey, taskDefinitionKey);

        if (!TaskEntityUtil.getCandidates(task).isEmpty() || StringUtils.isEmpty(task.getAssignee())) {
            return TaskAutoCompleteType.NOT_SATISFY_AUTO_APPROVAL_COND;
        }

        // find pre user task
//        BpmnModel bpmnModel = ProcessDefinitionUtil.getBpmnModel(execution.getProcessDefinitionId());
        UserTask preFlowElement = BpmnModelUtil.findPreFlowElement(commandContext, ((FlowNode) execution.getCurrentFlowElement()), UserTask.class);
        if (preFlowElement != null) {

            EntityCache entityCache = CommandContextUtil.getEntityCache(commandContext);
            List<HistoricTaskInstance> historicTaskInstances = entityCache.findInCache(HistoricTaskInstance.class);

            Optional<String> lastTaskAssignee = historicTaskInstances.stream()
                    .sorted(Ordering.natural().nullsFirst().onResultOf(HistoricTaskInstance::getEndTime).reverse())
                    .filter(taskCache -> taskCache.getTaskDefinitionKey().equals(preFlowElement.getId()))
                    .filter(taskCache -> taskCache.getParentTaskId() == null)
                    .map(TaskInfo::getAssignee)
                    .findFirst();

            if (lastTaskAssignee.isPresent()) {
                log.info("find lastTaskAssignee: {}", lastTaskAssignee);
            }

            if (lastTaskAssignee.orElse("").equals(task.getAssignee())) {
//                return TaskAutoCompleteType.CURRENT_APPROVER_IS_PREVIOUS_APPROVER;
            }
        }

        // history task history from db
        List<HistoricTaskInstanceEntity> tasksByProcessInstanceId = CommandContextUtil.getHistoricTaskService()
                .findHistoricTasksByProcessInstanceId(execution.getProcessInstanceId());

        EntityCache entityCache = CommandContextUtil.getEntityCache(commandContext);
        List<HistoricTaskInstance> historicTaskInstancesCache = entityCache.findInCache(HistoricTaskInstance.class)
                .stream().filter(t -> t.getEndTime() != null).toList();

        ArrayList<HistoricTaskInstance> taskInstances = Stream.concat(tasksByProcessInstanceId.stream(), historicTaskInstancesCache.stream())
                .collect(Collectors.collectingAndThen(Collectors.toMap(HistoricTaskInstance::getId, Function.identity(), (dbTask, cachedTask) -> cachedTask),
                        map -> new ArrayList<>(map.values())));

        Map<String, HistoricTaskInstance> historicTaskMap = taskInstances.stream()
                .collect(Collectors.toMap(
                        HistoricTaskInstance::getTaskDefinitionKey,
                        Function.identity(),
                        BinaryOperator.maxBy(Comparator.nullsLast(Comparator.comparing(HistoricTaskInstance::getEndTime)))
                ));

        Optional<HistoricTaskInstance> sameAssigneeHistoricTask = historicTaskMap.values().stream()
                .filter(historicTask -> historicTask.getAssignee().equals(task.getAssignee()))
                .filter(historicTask -> historicTask.getParentTaskId() == null)
                .findFirst();

        if (sameAssigneeHistoricTask.isPresent()) {
            return TaskAutoCompleteType.CURRENT_APPROVER_HAS_APPROVED_BEFORE;
        }


        // find start user id
        String startUserId = searchExecutionProperties(execution, ExecutionEntity::getStartUserId);

        if (StringUtils.equals(task.getAssignee(), startUserId)) {
            return TaskAutoCompleteType.CURRENT_APPROVER_IS_INITIATOR;
        }

        return TaskAutoCompleteType.NOT_SATISFY_AUTO_APPROVAL_COND;
    }

    private static String searchExecutionProperties(ExecutionEntity execution, Function<ExecutionEntity, String> propertyFun) {

        ExecutionEntity currentExecution = execution;
        String propertyValue = propertyFun.apply(currentExecution);

        while (propertyValue == null) {
            currentExecution = currentExecution.getParent();
            if (currentExecution != null) {
                propertyValue = propertyFun.apply(currentExecution);
            } else {
                break;
            }
        }
        return propertyValue;
    }
}
