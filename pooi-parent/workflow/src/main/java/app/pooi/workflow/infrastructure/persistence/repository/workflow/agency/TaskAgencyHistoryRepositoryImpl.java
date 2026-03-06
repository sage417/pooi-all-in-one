package app.pooi.workflow.infrastructure.persistence.repository.workflow.agency;

import app.pooi.workflow.domain.model.workflow.agency.TaskAgencyHistory;
import app.pooi.workflow.domain.repository.TaskAgencyHistoryRepository;
import app.pooi.workflow.infrastructure.persistence.converter.workflow.agency.TaskAgencyHistoryConverter;
import app.pooi.workflow.infrastructure.persistence.entity.workflow.delegate.TaskAgencyHistoryEntity;
import app.pooi.workflow.infrastructure.persistence.mapper.workflow.agency.TaskAgencyHistoryEntityMapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;


@Repository
@RequiredArgsConstructor
class TaskAgencyHistoryRepositoryImpl extends ServiceImpl<TaskAgencyHistoryEntityMapper, TaskAgencyHistoryEntity> implements TaskAgencyHistoryRepository {

    private final TaskAgencyHistoryConverter converter;

    @Override
    public void save(TaskAgencyHistory taskAgencyHistory) {
        super.save(converter.toEntity(taskAgencyHistory));
    }

}
