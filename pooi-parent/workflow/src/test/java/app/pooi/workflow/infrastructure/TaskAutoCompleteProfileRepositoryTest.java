package app.pooi.workflow.infrastructure;

import app.pooi.workflow.TenantInfoHolderExtension;
import app.pooi.workflow.domain.model.workflow.autocomplete.TaskAutoCompleteProfile;
import app.pooi.workflow.domain.repository.TaskAutoCompleteProfileRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.Assertions;
import org.flowable.common.engine.impl.cfg.multitenant.TenantInfoHolder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestConstructor;

import java.util.Optional;

@Slf4j
@ExtendWith(TenantInfoHolderExtension.class)
@SpringBootTest
@RequiredArgsConstructor
@TestConstructor(autowireMode = TestConstructor.AutowireMode.ALL)
public class TaskAutoCompleteProfileRepositoryTest {

    private final TaskAutoCompleteProfileRepository taskAutoCompleteProfileRepository;

    private final TenantInfoHolder tenantInfoHolder;

    @Test
    public void testSave() {
        TaskAutoCompleteProfile profile = new TaskAutoCompleteProfile();
        profile.setProcessDefinitionKey("key");
        profile.setTenantId(tenantInfoHolder.getCurrentTenantId());
        profile.setType(1);
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
        profile.setType(1);
        boolean save = taskAutoCompleteProfileRepository.save(profile);
        Assertions.assertThat(save).isTrue();

        taskAutoCompleteProfile = taskAutoCompleteProfileRepository.queryByDefinitionKey("key1");
        Assertions.assertThat(taskAutoCompleteProfile.isPresent()).isTrue();
        Assertions.assertThat(taskAutoCompleteProfile.get().getType()).isEqualTo(1);
    }
}
