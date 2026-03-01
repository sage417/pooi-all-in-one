/*
 * Copyright (c) 2024. Lorem ipsum dolor sit amet, consectetur adipiscing elit.
 * Morbi non lorem porttitor neque feugiat blandit. Ut vitae ipsum eget quam lacinia accumsan.
 * Etiam sed turpis ac ipsum condimentum fringilla. Maecenas magna.
 * Proin dapibus sapien vel ante. Aliquam erat volutpat. Pellentesque sagittis ligula eget metus.
 * Vestibulum commodo. Ut rhoncus gravida arcu.
 */

package app.pooi.workflow.infrastructure.persistence.service.impl.workflow.agency;

import app.pooi.workflow.infrastructure.persistence.entity.workflow.delegate.TaskAgencyProfileEntity;
import app.pooi.workflow.infrastructure.persistence.mapper.workflow.agency.TaskAgencyProfileEntityMapper;
import app.pooi.workflow.infrastructure.persistence.service.workflow.agency.TaskAgencyProfileEntityService;
import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class TaskAgencyProfileServiceImpl extends ServiceImpl<TaskAgencyProfileEntityMapper, TaskAgencyProfileEntity> implements TaskAgencyProfileEntityService {

    @Override
    public List<TaskAgencyProfileEntity> selectValidByProcessDefinitionKeyAndTenantId(String definitionKey, String tenantId) {
        return baseMapper.selectList(Wrappers.lambdaQuery(TaskAgencyProfileEntity.class)
                .eq(TaskAgencyProfileEntity::getProcessDefinitionKey, definitionKey)
                .eq(TaskAgencyProfileEntity::getTenantId, tenantId)
                .gt(TaskAgencyProfileEntity::getType, 0));
    }

    @Override
    public int saveTaskAgencyProfile(TaskAgencyProfileEntity entity) {
        return baseMapper.insertAgencyProfile(entity);
    }
}
