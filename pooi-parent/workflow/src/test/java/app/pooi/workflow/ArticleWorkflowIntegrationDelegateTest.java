package app.pooi.workflow;


import app.pooi.workflow.domain.model.enums.TaskAgencyType;
import app.pooi.workflow.domain.model.workflow.agency.TaskAgencyProfile;
import app.pooi.workflow.domain.repository.TaskAgencyProfileRepository;
import app.pooi.workflow.infrastructure.persistence.entity.workflow.eventpush.EventRecordEntity;
import app.pooi.workflow.infrastructure.persistence.repository.workflow.eventpush.EventRecordRepositoryImpl;
import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.google.common.collect.Lists;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.flowable.engine.RuntimeService;
import org.flowable.engine.TaskService;
import org.flowable.engine.test.Deployment;
import org.flowable.spring.impl.test.FlowableSpringExtension;
import org.flowable.task.api.Task;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.redisson.api.RedissonClient;
import org.springframework.boot.test.context.SpringBootTest;

import javax.annotation.Resource;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static app.pooi.workflow.TenantInfoHolderExtension.TENANT_APP_1;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
@ExtendWith(TenantInfoHolderExtension.class)
@ExtendWith(FlowableSpringExtension.class)
@SpringBootTest(classes = {})
class ArticleWorkflowIntegrationDelegateTest {
    @Resource
    private RuntimeService runtimeService;
    @Resource
    private TaskService taskService;
    @Resource
    private RedissonClient redissonClient;
    @Resource
    private EventRecordRepositoryImpl eventRecordRepository;
    @Resource
    private TaskAgencyProfileRepository taskAgencyProfileRepository;

    @SneakyThrows
    @Test
    @Deployment(resources = {"processes/article-workflow.bpmn20.xml"}, tenantId = TENANT_APP_1)
    void articleApprovalTest() {

        TaskAgencyProfile profile = new TaskAgencyProfile();
        profile.setTenantId(TENANT_APP_1);
        profile.setProcessDefinitionKey("articleReview");
        profile.setDelegator("assignee1");
        profile.setDelegatee(Lists.newArrayList("delegatee1"));
        profile.setAgencyType(TaskAgencyType.DELEGATE);
        taskAgencyProfileRepository.save(profile);

        Map<String, Object> variables = new HashMap<String, Object>();
        variables.put("author", "test@baeldung.com");
        variables.put("url", "http://baeldung.com/dummy");
        runtimeService.startProcessInstanceByKeyAndTenantId("articleReview", variables, TENANT_APP_1);
        Task task = taskService.createTaskQuery()
                .singleResult();
        assertEquals("Review the submitted tutorial", task.getName());
        assertEquals("assignee1", task.getAssignee());

        variables.put("approved", true);
        taskService.setAssignee(task.getId(), "target");
        taskService.complete(task.getId(), variables);
        assertEquals(0, runtimeService.createProcessInstanceQuery()
                .count());
        TimeUnit.SECONDS.sleep(5);
        // wait
        assertEquals(16, eventRecordRepository.count(Wrappers.lambdaQuery(EventRecordEntity.class)
                .eq(EventRecordEntity::getProcessInstanceId, task.getProcessInstanceId())), "");
    }
}
