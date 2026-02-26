package app.pooi.workflow.application.service;

import app.pooi.tenant.multitenancy.ApplicationInfoHolder;
import groovy.util.logging.Slf4j;
import org.flowable.engine.RepositoryService;
import org.flowable.engine.repository.Deployment;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;

@Slf4j
@Component
public class ProcessDefinitionDeployAppService {

    @Resource
    private RepositoryService repositoryService;

//    @Resource
//    private ModelService modelService;

    @Resource
    private ApplicationInfoHolder applicationInfoHolder;

    public void deployResource(String resource, String key, String name) {
        Deployment deployment = repositoryService.createDeployment()
                .key(key)
                .name(name)
                .tenantId(applicationInfoHolder.getApplicationCode())
                .addClasspathResource(resource)
                .deploy();
    }

    public void deployModel(String modelId, String key, String name) {

        // model (json) -> bpmn model
//        Model model = modelService.getModel(modelId);
//        BpmnModel bpmnModel = modelService.getBpmnModel(model);
        // xml -> bpmn model
//        bpmnXMLConverter.convertToBpmnModel();

        Deployment deployment = repositoryService.createDeployment()
                .key(key)
                .name(name)
                .tenantId(applicationInfoHolder.getApplicationCode())
                .addBpmnModel(key + ".bpmn20.xml", null)
                .deploy();
    }
}
