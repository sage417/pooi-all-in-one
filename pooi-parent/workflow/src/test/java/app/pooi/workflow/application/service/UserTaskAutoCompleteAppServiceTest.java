package app.pooi.workflow.application.service;

import app.pooi.workflow.TenantInfoHolderExtension;
import app.pooi.workflow.domain.model.workflow.autocomplete.TaskAutoCompleteProfile;
import app.pooi.workflow.domain.model.workflow.comment.Comment;
import app.pooi.workflow.domain.repository.TaskAutoCompleteProfileRepository;
import app.pooi.workflow.domain.service.comment.CommentService;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.flowable.common.engine.impl.identity.Authentication;
import org.flowable.engine.RuntimeService;
import org.flowable.engine.TaskService;
import org.flowable.engine.test.Deployment;
import org.flowable.task.api.Task;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestConstructor;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static app.pooi.workflow.TenantInfoHolderExtension.TENANT_APP_1;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
@ExtendWith(TenantInfoHolderExtension.class)
//@ExtendWith(FlowableSpringExtension.class)
@SpringBootTest()
@TestConstructor(autowireMode = TestConstructor.AutowireMode.ALL)
@RequiredArgsConstructor
class UserTaskAutoCompleteAppServiceTest {

    private final RuntimeService runtimeService;

    private final TaskService taskService;

    private final CommentService commentService;

    private final TaskAutoCompleteProfileRepository autoCompleteProfileRepository;

    @Test
    @SneakyThrows
    @Deployment(resources = {"processes/article-workflow-auto-complete.bpmn20.xml"}, tenantId = TENANT_APP_1)
    void satisfyAutoCompleteCond() {

        addProfile(1, "articleReview-autocomplete");

        Map<String, Object> variables = new HashMap<>();
        variables.put("author", "test@baeldung.com");
        variables.put("url", "http://baeldung.com/dummy");
        runtimeService.startProcessInstanceByKeyAndTenantId("articleReview-autocomplete", variables, TENANT_APP_1);
        assertEquals(1, runtimeService.createProcessInstanceQuery().count());
        Task task = taskService.createTaskQuery()
                .singleResult();
        assertEquals("Review the submitted tutorial", task.getName());
        variables.put("approved", true);
        taskService.setAssignee(task.getId(), "assignee1");
        assertEquals(1, taskService.createTaskQuery().count());
        assertEquals(1, taskService.createTaskQuery().taskAssignee("assignee1").count());

        taskService.complete(task.getId());
        assertEquals(0, runtimeService.createProcessInstanceQuery().count());

        List<Comment> comments = commentService.listByInstanceId(task.getProcessInstanceId());
        assertEquals("AUTO_COMPLETE", comments.getFirst().getType());
    }


    @Test
    @SneakyThrows
    @Deployment(resources = {"processes/article-workflow-auto-complete.bpmn20.xml"}, tenantId = TENANT_APP_1)
    void satisfyAutoCompleteCond2() {

        Map<String, Object> variables = new HashMap<>();
        variables.put("author", "test@baeldung.com");
        variables.put("url", "http://baeldung.com/dummy");
        runtimeService.startProcessInstanceByKeyAndTenantId("articleReview-autocomplete", variables, TENANT_APP_1);
        assertEquals(1, runtimeService.createProcessInstanceQuery().count());
        Task task = taskService.createTaskQuery()
                .singleResult();
        assertEquals("Review the submitted tutorial", task.getName());
        variables.put("approved", true);
        taskService.setAssignee(task.getId(), "assignee2");
        assertEquals(1, taskService.createTaskQuery().count());
        assertEquals(1, taskService.createTaskQuery().taskAssignee("assignee2").count());

        taskService.complete(task.getId());
        assertEquals(1, taskService.createTaskQuery().count());
        assertEquals(1, taskService.createTaskQuery().taskAssignee("assignee1").count());

        runtimeService.deleteProcessInstance(task.getProcessInstanceId(), "TEST_CASE_DELETE");
    }

    @Test
    @SneakyThrows
    @Deployment(resources = {"processes/article-workflow-auto-complete-start-user-id.bpmn20.xml"}, tenantId = TENANT_APP_1)
    void satisfyAutoCompleteCondStartId() {

        addProfile(3, "articleReview-autocomplete-start-user-id");

        Map<String, Object> variables = new HashMap<>();
        variables.put("author", "test@baeldung.com");
        variables.put("url", "http://baeldung.com/dummy");

        Authentication.setAuthenticatedUserId("start_user_id");
        runtimeService.startProcessInstanceByKeyAndTenantId("articleReview-autocomplete-start-user-id", variables, TENANT_APP_1);
        assertEquals(1, runtimeService.createProcessInstanceQuery().count());

        Task task = taskService.createTaskQuery()
                .singleResult();
        assertEquals("Review the submitted tutorial", task.getName());
        variables.put("approved", true);
        taskService.setAssignee(task.getId(), "assignee1");
        assertEquals(1, taskService.createTaskQuery().count());
        assertEquals(1, taskService.createTaskQuery().taskAssignee("assignee1").count());

        taskService.complete(task.getId());
        assertEquals(0, runtimeService.createProcessInstanceQuery().count());

        List<Comment> comments = commentService.listByInstanceId(task.getProcessInstanceId());
        assertEquals("AUTO_COMPLETE", comments.getFirst().getType());
    }

    private void addProfile(int type, String processDefinitionKey) {
        TaskAutoCompleteProfile taskAutoCompleteProfile = new TaskAutoCompleteProfile();
        taskAutoCompleteProfile.setType(type);
        taskAutoCompleteProfile.setTenantId(TENANT_APP_1);
        taskAutoCompleteProfile.setProcessDefinitionKey(processDefinitionKey);
        autoCompleteProfileRepository.save(taskAutoCompleteProfile);
    }
}