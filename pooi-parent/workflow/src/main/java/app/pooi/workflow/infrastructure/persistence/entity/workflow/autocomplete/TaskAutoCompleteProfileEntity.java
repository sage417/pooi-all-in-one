package app.pooi.workflow.infrastructure.persistence.entity.workflow.autocomplete;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;
import lombok.experimental.Accessors;

import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDateTime;

@Accessors(chain = true)
@Data
@TableName(value = "t_workflow_auto_complete_profile")
public class TaskAutoCompleteProfileEntity implements Serializable {

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
