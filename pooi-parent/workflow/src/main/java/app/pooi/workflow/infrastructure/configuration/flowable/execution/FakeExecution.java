package app.pooi.workflow.infrastructure.configuration.flowable.execution;

import org.flowable.bpmn.model.FlowElement;
import org.flowable.engine.delegate.ReadOnlyDelegateExecution;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class FakeExecution implements ReadOnlyDelegateExecution {

    private final Map<String, Object> variables = new HashMap<>();

    public FakeExecution(Map<String, Object> variables) {
        this.variables.putAll(variables);
        this.variables.put("execution", this);
    }

    @Override
    public String getId() {
        return "";
    }

    @Override
    public String getProcessInstanceId() {
        return "";
    }

    @Override
    public String getRootProcessInstanceId() {
        return "";
    }

    @Override
    public String getEventName() {
        return "";
    }

    @Override
    public String getProcessInstanceBusinessKey() {
        return "";
    }

    @Override
    public String getProcessInstanceBusinessStatus() {
        return "";
    }

    @Override
    public String getProcessDefinitionId() {
        return "";
    }

    @Override
    public String getPropagatedStageInstanceId() {
        return "";
    }

    @Override
    public String getParentId() {
        return "";
    }

    @Override
    public String getSuperExecutionId() {
        return "";
    }

    @Override
    public String getCurrentActivityId() {
        return "";
    }

    @Override
    public FlowElement getCurrentFlowElement() {
        return null;
    }

    @Override
    public boolean isActive() {
        return false;
    }

    @Override
    public boolean isEnded() {
        return false;
    }

    @Override
    public boolean isConcurrent() {
        return false;
    }

    @Override
    public boolean isProcessInstanceType() {
        return false;
    }

    @Override
    public boolean isScope() {
        return false;
    }

    @Override
    public boolean isMultiInstanceRoot() {
        return false;
    }

    @Override
    public boolean hasVariable(String variableName) {
        return variables.containsKey(variableName);
    }

    @Override
    public Object getVariable(String variableName) {
        return variables.get(variableName);
    }

    @Override
    public String getTenantId() {
        return "";
    }

    @Override
    public Set<String> getVariableNames() {
        return this.variables.keySet();
    }
}
