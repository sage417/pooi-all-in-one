package app.pooi.workflow.infrastructure.persistence.repository.workflow.eventpush;

import app.pooi.workflow.domain.repository.EventPushRecordRepository;
import app.pooi.workflow.infrastructure.persistence.converter.workflow.eventpush.EventPushRecordConverter;
import app.pooi.workflow.infrastructure.persistence.entity.workflow.eventpush.EventPushRecordEntity;
import app.pooi.workflow.infrastructure.persistence.mapper.workflow.eventpush.EventPushRecordEntityMapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
class EventPushRecordRepositoryImpl extends ServiceImpl<EventPushRecordEntityMapper, EventPushRecordEntity> implements EventPushRecordRepository {

    private final EventPushRecordConverter converter;
}
