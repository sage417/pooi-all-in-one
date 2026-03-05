package app.pooi.workflow.infrastructure.persistence.repository.workflow.agency;

import app.pooi.workflow.domain.model.workflow.agency.TaskAgencyProfile;
import app.pooi.workflow.domain.repository.TaskAgencyProfileRepository;
import app.pooi.workflow.infrastructure.persistence.converter.workflow.agency.TaskAgencyProfileConverter;
import app.pooi.workflow.infrastructure.persistence.entity.workflow.delegate.TaskAgencyProfileEntity;
import app.pooi.workflow.infrastructure.persistence.service.workflow.agency.TaskAgencyProfileEntityService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@RequiredArgsConstructor
public class TaskAgencyProfileRepositoryImpl implements TaskAgencyProfileRepository {

    private final TaskAgencyProfileEntityService approvalDelegateConfigEntityService;

    private final TaskAgencyProfileConverter converter;

    @Override
    public List<TaskAgencyProfile> selectValidByProcessDefinitionKeyAndTenantId(String definitionKey, String tenantId) {
        List<TaskAgencyProfileEntity> entities = approvalDelegateConfigEntityService.selectValidByProcessDefinitionKeyAndTenantId(definitionKey, tenantId);
        return entities.stream().map(converter::toModel).toList();
    }

    @Override
    public void save(TaskAgencyProfile profile) {
        approvalDelegateConfigEntityService.saveTaskAgencyProfile(converter.toEntity(profile));
    }
}
