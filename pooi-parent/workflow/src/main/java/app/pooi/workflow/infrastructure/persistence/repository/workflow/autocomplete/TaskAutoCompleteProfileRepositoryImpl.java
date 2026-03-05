package app.pooi.workflow.infrastructure.persistence.repository.workflow.autocomplete;

import app.pooi.workflow.domain.model.workflow.autocomplete.TaskAutoCompleteProfile;
import app.pooi.workflow.domain.repository.TaskAutoCompleteProfileRepository;
import app.pooi.workflow.infrastructure.persistence.converter.workflow.autocomplete.TaskAutoCompleteProfileConverter;
import app.pooi.workflow.infrastructure.persistence.entity.workflow.autocomplete.TaskAutoCompleteProfileEntity;
import app.pooi.workflow.infrastructure.persistence.mapper.workflow.autocomplete.TaskAutoCompleteProfileMapper;
import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
@RequiredArgsConstructor
public class TaskAutoCompleteProfileRepositoryImpl extends ServiceImpl<TaskAutoCompleteProfileMapper, TaskAutoCompleteProfileEntity> implements TaskAutoCompleteProfileRepository {

    private final TaskAutoCompleteProfileConverter converter;

    @Override
    public boolean save(TaskAutoCompleteProfile taskAutoCompleteProfile) {
        TaskAutoCompleteProfileEntity entity = converter.toEntity(taskAutoCompleteProfile);
        return super.save(entity);
    }

    @Override
    public Optional<TaskAutoCompleteProfile> queryByDefinitionKey(String definitionKey) {
        TaskAutoCompleteProfileEntity entity = getBaseMapper().selectOne(Wrappers.lambdaQuery(TaskAutoCompleteProfileEntity.class)
                .eq(TaskAutoCompleteProfileEntity::getProcessDefinitionKey, definitionKey));
        return Optional.ofNullable(converter.toModel(entity));
    }
}
