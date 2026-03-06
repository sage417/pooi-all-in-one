package app.pooi.workflow.infrastructure.persistence.repository.workflow.eventpush;

import app.pooi.workflow.domain.model.workflow.eventpush.EventRecord;
import app.pooi.workflow.domain.repository.EventRecordRepository;
import app.pooi.workflow.infrastructure.persistence.converter.workflow.eventpush.EventRecordConverter;
import app.pooi.workflow.infrastructure.persistence.entity.workflow.eventpush.EventRecordEntity;
import app.pooi.workflow.infrastructure.persistence.mapper.workflow.eventpush.EventRecordEntityMapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;

@Repository
@RequiredArgsConstructor
public class EventRecordRepositoryImpl extends ServiceImpl<EventRecordEntityMapper, EventRecordEntity> implements EventRecordRepository {

    private final EventRecordConverter converter;

    @Override
    public boolean saveAll(Collection<EventRecord> eventRecords, int batchSize) {
        List<EventRecordEntity> entities = eventRecords.stream().map(converter::toEntity).toList();
        return super.saveBatch(entities, batchSize);
    }
}
