CREATE TABLE `t_workflow_comment`
(
    `id`                    bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
    `tenant_id`             varchar(255) NOT NULL DEFAULT '' COMMENT '租户标识',
    `process_definition_id` varchar(255) NOT NULL DEFAULT '' COMMENT '流程定义id',
    `process_instance_id`   varchar(255) NOT NULL DEFAULT '' COMMENT '流程实例id',
    `node_id`               varchar(255) NOT NULL DEFAULT '' COMMENT '节点id',
    `task_id`               varchar(255) NOT NULL DEFAULT '' COMMENT '任务id',
    `type`                  varchar(255) NOT NULL DEFAULT '' COMMENT '类型',
    `operator_account`      varchar(255) NOT NULL DEFAULT '' COMMENT '操作人账号',
    `operation_detail`      json         NULL COMMENT '操作详情',
    `create_time`           datetime(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `update_time`           datetime(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (`id`)
) ENGINE = InnoDB
  AUTO_INCREMENT = 0
  DEFAULT CHARSET = utf8mb4 COMMENT '流程操作记录';

CREATE TABLE `t_workflow_event_record`
(
    `id`                  bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
    event_id              varchar(255) NOT NULL DEFAULT '' COMMENT '事件id',
    tenant_id             varchar(255) NOT NULL DEFAULT '' COMMENT '租户标识',
    process_definition_id varchar(255) NOT NULL DEFAULT '' COMMENT '流程定义id',
    process_instance_id   varchar(255) NOT NULL DEFAULT '' COMMENT '流程实例id',
    subject_id            varchar(255) NOT NULL DEFAULT '' COMMENT '租户标识',
    event_type            varchar(127) NOT NULL DEFAULT '' COMMENT '事件类型',
    event                 json         NULL COMMENT '事件详情',
    `create_time`         datetime(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `update_time`         datetime(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (`id`)
) ENGINE = InnoDB
  AUTO_INCREMENT = 0
  DEFAULT CHARSET = utf8mb4 COMMENT '事件快照记录';

CREATE TABLE `t_workflow_event_push_record`
(
    `id`                  bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
    event_id              varchar(255) NOT NULL DEFAULT '' COMMENT '事件id',
    tenant_id             varchar(255) NOT NULL DEFAULT '' COMMENT '租户标识',
    process_definition_id varchar(255) NOT NULL DEFAULT '' COMMENT '流程定义id',
    process_instance_id   varchar(255) NOT NULL DEFAULT '' COMMENT '流程实例id',
    subject_id            varchar(255) NOT NULL DEFAULT '' COMMENT '租户标识',
    event_type            varchar(127) NOT NULL DEFAULT '' COMMENT '事件类型',
    event                 json         NULL COMMENT '事件详情',
    `create_time`         datetime(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `update_time`         datetime(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (`id`)
) ENGINE = InnoDB
  AUTO_INCREMENT = 0
  DEFAULT CHARSET = utf8mb4 COMMENT '事件推送记录';

CREATE TABLE `t_workflow_event_push_profile`
(
    `id`          bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
    `tenant_id`   varchar(255) NOT NULL DEFAULT '' COMMENT '租户标识',
    `type`        varchar(10)  NOT NULL DEFAULT '' COMMENT '配置类型',
    `profile`     json         NULL COMMENT '配置',
    `create_time` datetime(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `update_time` datetime(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (`id`)
) ENGINE = InnoDB
  AUTO_INCREMENT = 0
  DEFAULT CHARSET = utf8mb4 COMMENT '事件推送配置';

CREATE TABLE `t_workflow_task_agency_profile`
(
    `id`                     bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
    `tenant_id`              varchar(255)     NOT NULL DEFAULT '' COMMENT '租户标识',
    `process_definition_key` varchar(255)     NOT NULL DEFAULT '' COMMENT '流程定义id',
    `type`                   tinyint UNSIGNED NOT NULL DEFAULT 0 COMMENT '委托类型 0:无效 1:代理 2:共享',
    `on_behalf_of`           tinyint UNSIGNED NOT NULL DEFAULT 0 COMMENT '代操作',
    `delegator`              varchar(255)     NOT NULL COMMENT '委托人',
    `delegatee`              json COMMENT '代理人',
    `valid_time`             datetime(3)      NULL COMMENT '生效时间',
    `invalid_time`           datetime(3)      NULL COMMENT '失效时间',
    `create_time`            datetime(3)      NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `update_time`            datetime(3)      NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    `is_delete`              tinyint UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (`id`)
) ENGINE = InnoDB
  AUTO_INCREMENT = 0
  DEFAULT CHARSET = utf8mb4 COMMENT '审批委托配置表';

CREATE TABLE `t_workflow_task_agency_history`
(
    `id`                     bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
    `tenant_id`              varchar(255)     NOT NULL DEFAULT '' COMMENT '租户标识',
    `process_definition_key` varchar(255)     NOT NULL DEFAULT '' COMMENT '流程定义id',
    `process_instance_id`    varchar(255)     NOT NULL DEFAULT '' COMMENT '流程实例id',
    `task_definition_key` varchar(255) NOT NULL DEFAULT '' COMMENT '任务节点id',
    `task_id`                varchar(255)     NOT NULL DEFAULT '' COMMENT '任务id',
    `type`                   tinyint UNSIGNED NOT NULL DEFAULT 0 COMMENT '委托类型 0:无效 1:全权委托 2:协助审批',
    `delegate_details`    json COMMENT '代理人',
    `create_time`            datetime(3)      NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `update_time`            datetime(3)      NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (`id`)
) ENGINE = InnoDB
  AUTO_INCREMENT = 0
  DEFAULT CHARSET = utf8mb4 COMMENT '审批委托记录表';

TRUNCATE TABLE t_workflow_event_push_profile;

insert into t_workflow_event_push_profile (tenant_id, type, profile)
values ('app1', 'grpc', '{
  "target": "discovery:///pooi-workflow-core",
  "fullServiceName": "app.pooi.rpc.workflow.HelloWorldService",
  "methodName": "SayHello"
}');

TRUNCATE TABLE t_workflow_task_agency_profile;

insert into t_workflow_task_agency_profile (tenant_id, type, delegator, delegatee)
values ('app1', 1, 'a', JSON_ARRAY('b'));