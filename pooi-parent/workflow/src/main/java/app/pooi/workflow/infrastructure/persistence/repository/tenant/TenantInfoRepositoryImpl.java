package app.pooi.workflow.infrastructure.persistence.repository.tenant;

import app.pooi.workflow.domain.model.tenant.TenantInfo;
import app.pooi.workflow.domain.repository.TenantInfoRepository;
import app.pooi.workflow.infrastructure.persistence.converter.tenant.TenantInfoConverter;
import app.pooi.workflow.infrastructure.persistence.entity.tenant.TenantInfoEntity;
import app.pooi.workflow.infrastructure.persistence.mapper.tenant.TenantInfoEntityMapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.stream.Collectors;

@Repository
@RequiredArgsConstructor
class TenantInfoRepositoryImpl extends ServiceImpl<TenantInfoEntityMapper, TenantInfoEntity> implements TenantInfoRepository {

    private final TenantInfoConverter converter;

    @Override
    public List<TenantInfo> listTenant() {
        return super.list().stream()
                .map(converter::toModel).collect(Collectors.toList());
    }
}
