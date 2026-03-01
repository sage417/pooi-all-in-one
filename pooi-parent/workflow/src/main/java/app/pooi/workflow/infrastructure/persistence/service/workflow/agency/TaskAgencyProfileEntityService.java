/*
 * Copyright (c) 2024. Lorem ipsum dolor sit amet, consectetur adipiscing elit.
 * Morbi non lorem porttitor neque feugiat blandit. Ut vitae ipsum eget quam lacinia accumsan.
 * Etiam sed turpis ac ipsum condimentum fringilla. Maecenas magna.
 * Proin dapibus sapien vel ante. Aliquam erat volutpat. Pellentesque sagittis ligula eget metus.
 * Vestibulum commodo. Ut rhoncus gravida arcu.
 */

package app.pooi.workflow.infrastructure.persistence.service.workflow.agency;

import app.pooi.workflow.infrastructure.persistence.entity.workflow.delegate.TaskAgencyProfileEntity;
import com.baomidou.mybatisplus.extension.service.IService;

import java.util.List;

public interface TaskAgencyProfileEntityService extends IService<TaskAgencyProfileEntity> {

    List<TaskAgencyProfileEntity> selectValidByProcessDefinitionKeyAndTenantId(String definitionKey, String tenantId);

    int saveTaskAgencyProfile(TaskAgencyProfileEntity entity);
}
