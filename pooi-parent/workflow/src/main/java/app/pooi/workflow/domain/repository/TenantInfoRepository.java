package app.pooi.workflow.domain.repository;

import app.pooi.workflow.domain.model.tenant.TenantInfo;

import java.util.List;

public interface TenantInfoRepository {

    List<TenantInfo> listTenant();
}
