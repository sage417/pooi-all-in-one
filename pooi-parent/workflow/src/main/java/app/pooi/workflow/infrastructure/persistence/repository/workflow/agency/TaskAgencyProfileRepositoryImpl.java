package app.pooi.workflow.infrastructure.persistence.repository.workflow.agency;

import app.pooi.workflow.domain.model.workflow.agency.TaskAgencyProfile;
import app.pooi.workflow.domain.repository.TaskAgencyProfileRepository;
import app.pooi.workflow.infrastructure.persistence.converter.workflow.agency.TaskAgencyProfileConverter;
import app.pooi.workflow.infrastructure.persistence.entity.workflow.delegate.TaskAgencyProfileEntity;
import app.pooi.workflow.infrastructure.persistence.mapper.workflow.agency.TaskAgencyProfileEntityMapper;
import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@RequiredArgsConstructor
class TaskAgencyProfileRepositoryImpl extends ServiceImpl<TaskAgencyProfileEntityMapper, TaskAgencyProfileEntity> implements TaskAgencyProfileRepository {

    private final TaskAgencyProfileConverter converter;

    @Override
    public List<TaskAgencyProfile> selectValidByProcessDefinitionKeyAndTenantId(String definitionKey, String tenantId) {
        List<TaskAgencyProfileEntity> entities = getBaseMapper().selectList(Wrappers.lambdaQuery(TaskAgencyProfileEntity.class)
                .eq(TaskAgencyProfileEntity::getProcessDefinitionKey, definitionKey)
                .eq(TaskAgencyProfileEntity::getTenantId, tenantId)
                .gt(TaskAgencyProfileEntity::getType, 0));
        return entities.stream().map(converter::toModel).toList();
    }

    @Override
    public void save(TaskAgencyProfile profile) {
        getBaseMapper().insertAgencyProfile(converter.toEntity(profile));
    }
}
