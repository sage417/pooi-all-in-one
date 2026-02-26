package app.pooi.workflow.domain.model.workflow.core;

import app.pooi.basic.expection.BusinessException;
import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.StringUtils;
import org.flowable.engine.RepositoryService;
import org.flowable.engine.RuntimeService;
import org.flowable.engine.repository.ProcessDefinition;
import org.flowable.engine.runtime.ProcessInstance;
import org.flowable.engine.runtime.ProcessInstanceBuilder;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.Map;

@Component
public class ProcessInstanceService {

    @Resource
    private RepositoryService repositoryService;

    @Resource
    private RuntimeService runtimeService;


    public ProcessInstance startInstance(String processDefinitionKey, Integer processDefinitionVersion,
                                         String instanceName, String businessKey,
                                         Map<String, Object> variables,
                                         String applicationCode) {

        ProcessInstanceBuilder instanceBuilder = runtimeService.createProcessInstanceBuilder().tenantId(applicationCode);

        if (StringUtils.isNotEmpty(instanceName)) {
            instanceBuilder = instanceBuilder.name(instanceName);
        }

        if (StringUtils.isNotEmpty(businessKey)) {
            instanceBuilder = instanceBuilder.businessKey(businessKey);
        }

        if (MapUtils.isNotEmpty(variables)) {
            instanceBuilder = instanceBuilder.variables(variables);
        }

        if (processDefinitionVersion == null) {
            instanceBuilder = instanceBuilder.processDefinitionKey(processDefinitionKey);
        } else {
            ProcessDefinition definition = repositoryService.createProcessDefinitionQuery()
                    .processDefinitionTenantId(applicationCode)
                    .processDefinitionKey(processDefinitionKey)
                    .processDefinitionVersion(processDefinitionVersion)
                    .singleResult();

            if (definition == null) {
                throw new BusinessException("bizExp.process.definition.not_found", processDefinitionKey, processDefinitionVersion);
            }
            instanceBuilder = instanceBuilder.processDefinitionId(definition.getId());
        }

        // inherit tenant_id from definition
        return instanceBuilder.start();
    }
}
