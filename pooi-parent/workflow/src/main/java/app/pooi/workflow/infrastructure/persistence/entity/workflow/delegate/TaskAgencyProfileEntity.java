/*
 * Copyright (c) 2024. Lorem ipsum dolor sit amet, consectetur adipiscing elit.
 * Morbi non lorem porttitor neque feugiat blandit. Ut vitae ipsum eget quam lacinia accumsan.
 * Etiam sed turpis ac ipsum condimentum fringilla. Maecenas magna.
 * Proin dapibus sapien vel ante. Aliquam erat volutpat. Pellentesque sagittis ligula eget metus.
 * Vestibulum commodo. Ut rhoncus gravida arcu.
 */

package app.pooi.workflow.infrastructure.persistence.entity.workflow.delegate;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.baomidou.mybatisplus.extension.handlers.JacksonTypeHandler;
import lombok.Data;
import lombok.experimental.Accessors;

import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.List;

@Accessors(chain = true)
@Data
@TableName(value = "t_workflow_task_agency_profile", autoResultMap = true)
public class TaskAgencyProfileEntity implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * id
     */
    @TableId(type = IdType.AUTO)
    private Long id;

    /**
     * 租户标识
     */
    private String tenantId;

    /**
     * 流程定义key
     */
    private String processDefinitionKey;

    /**
     * 委托类型 0:无效 1:代理 2:共享
     */
    private Integer type;

    /**
     * 代理
     */
    private Integer onBehalfOf;

    /**
     * 委托人
     */
    private String delegator;

    /**
     * 代理人
     */
    @TableField(typeHandler = JacksonTypeHandler.class)
    private List<String> delegatee;

    /**
     * 生效时间
     */
    private LocalDateTime validTime;

    /**
     * 失效时间
     */
    private LocalDateTime invalidTime;

    /**
     * create_time
     */
    private LocalDateTime createTime;

    /**
     * update_time
     */
    private LocalDateTime updateTime;

    /**
     * is_delete
     */
    private Integer isDelete;
}
