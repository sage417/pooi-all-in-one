package app.pooi.workflow.infrastructure;

import app.pooi.workflow.TenantInfoHolderExtension;
import app.pooi.workflow.domain.model.workflow.autocomplete.TaskAutoCompleteProfile;
import app.pooi.workflow.domain.repository.TaskAutoCompleteProfileRepository;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.Assertions;
import org.flowable.common.engine.impl.cfg.multitenant.TenantInfoHolder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;

import javax.annotation.Resource;
import java.util.Optional;

@Slf4j
@ExtendWith(TenantInfoHolderExtension.class)
@SpringBootTest
public class TaskAutoCompleteProfileRepositoryTest {

    @Resource
    private TaskAutoCompleteProfileRepository taskAutoCompleteProfileRepository;

    @Resource
    private TenantInfoHolder tenantInfoHolder;

    @Test
    public void testSave() {
        TaskAutoCompleteProfile profile = new TaskAutoCompleteProfile();
        profile.setProcessDefinitionKey("key");
        profile.setTenantId(tenantInfoHolder.getCurrentTenantId());
        boolean save = taskAutoCompleteProfileRepository.save(profile);

        Assertions.assertThat(save).isTrue();
    }

    @Test
    public void testQueryByDefinitionKey() {
        Optional<TaskAutoCompleteProfile> taskAutoCompleteProfile = taskAutoCompleteProfileRepository.queryByDefinitionKey("key1");
        Assertions.assertThat(taskAutoCompleteProfile.isPresent()).isFalse();

        TaskAutoCompleteProfile profile = new TaskAutoCompleteProfile();
        profile.setProcessDefinitionKey("key1");
        profile.setTenantId(tenantInfoHolder.getCurrentTenantId());
        boolean save = taskAutoCompleteProfileRepository.save(profile);

        taskAutoCompleteProfile = taskAutoCompleteProfileRepository.queryByDefinitionKey("key1");
        Assertions.assertThat(taskAutoCompleteProfile.isPresent()).isTrue();
    }
}
