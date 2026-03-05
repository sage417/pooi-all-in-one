package app.pooi.workflow.domain.model.workflow.autocomplete;


import lombok.Data;

import java.time.LocalDateTime;

@Data
public class TaskAutoCompleteProfile {

    /**
     * id
     */
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
     * 类型
     */
    private Integer type;

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
