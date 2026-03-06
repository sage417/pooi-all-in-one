package app.pooi.workflow.infrastructure.persistence.repository.workflow.eventpush;

import app.pooi.workflow.domain.model.workflow.eventpush.EventPushProfile;
import app.pooi.workflow.domain.repository.EventPushProfileRepository;
import app.pooi.workflow.infrastructure.persistence.converter.workflow.eventpush.EventPushProfileConverter;
import app.pooi.workflow.infrastructure.persistence.entity.workflow.eventpush.EventPushProfileEntity;
import app.pooi.workflow.infrastructure.persistence.mapper.workflow.eventpush.EventPushProfileEntityMapper;
import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.stream.Collectors;

@Repository
@RequiredArgsConstructor
class EventPushProfileRepositoryImpl extends ServiceImpl<EventPushProfileEntityMapper, EventPushProfileEntity> implements EventPushProfileRepository {

    private final EventPushProfileConverter converter;

    public List<EventPushProfile> findByTenantId(String tenantId) {
        List<EventPushProfileEntity> entities = super.list(
                Wrappers.lambdaQuery(EventPushProfileEntity.class)
                        .eq(EventPushProfileEntity::getTenantId, tenantId)
        );
        return entities.stream().map(converter::toModel).collect(Collectors.toList());
    }

}
