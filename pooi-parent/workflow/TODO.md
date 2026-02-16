- [x] 事件推送
- [x] shardingsphere接入
- [x] 动态加签 app.pooi.workflow.application.service.UserTaskAddSignAppService.addSignTask
- [x] 分布式缓存 app.pooi.workflow.infrastructure.configuration.flowable.engine.ProcessDefinitionDeploymentCache
- [x] 分享/传阅 app.pooi.workflow.application.service.UserTaskOperationAppService.addCirculate
- [x] 审批历史 app.pooi.workflow.domain.service.comment.CommentService
- [x] 任务回退/跳转 app.pooi.workflow.application.service.ProcessInstanceMoveAppService.rollback
- [x] 任务挂起 app.pooi.workflow.application.service.UserTaskSuspendAppService
- [ ] 审批全权代理/共享 app.pooi.workflow.application.service.UserTaskAgencyAppService
- [ ] 任务条件自动审批 app.pooi.workflow.application.service.UserTaskAutoCompleteAppService
- [ ] 审批人异常处理
  app.pooi.workflow.infrastructure.configuration.flowable.FlowableCreateUserTaskInterceptor.afterCreateUserTask
- [ ] 任务超时处理
- [ ] 办理人员规则/审批人对接人员/组织关系 app.pooi.workflow.application.service.OrgQueryAppService
- [ ] 流程流转显示 app.pooi.workflow.application.service.ProcessDiagramAppService
- [ ] ~~标题自动计算~~
- [ ] 多语言
- [x] 测试
- [x] 对接iam

### 代操作/代理/共享/加签 定义

任务代办(Task Agency) 为 代操作/代理/共享 统称， 实际为若某一任务的审批候选人匹配规则，则对该任务的审批候选人进行修改

- 代操作(On Behalf Of)： 允许他人以原审批人名义进行审批，审批人显示为原审批人，非真实操作人

代操作是显示审批人的一种行为，无论如何修改任务审批候选人， 在展示时显示由原审批人操作

- 代理(Delegation)： 全权委托他人审批，原审批人看不到审批，也无法处理审批

代理匹配规则时， 任务的原审批人替换为代理人

- 共享(Share)： 邀请他人协助审批，原审批人和协助人可共同审批

共享匹配规则时， 任务的审批候选人增加协助人

代理、共享 无论指定多少人，仅需一人处理审批即完成， **代理规则优先于共享规则**，既先执行代理规则，后执行共享规则

| 类型                | 显示审批人            | 可审批范围 | 穿透 |
|-------------------|------------------|-------|----|
| 显示代理(常见)          | B (由 A 委托审批)     | B     |    |
| 隐式代理(不常见，常见于移交操作) | B                | B     |    |
| 代操作 + 代理(不常见)     | A                | B     |    |
| 显示共享(常见)          | A & B (由 A 共享审批) | A + B |    |
| 代操作 + 共享(不常见)     | A                | A + B |    |

移交 ： 显示和审批范围规则和隐式代理相同，由任务原审批人指定， 对该任务的审批候选人进行修改

(动态)前/后加签(Add Sign)： 邀请他人协助共同审批，需要所有人都处理完毕， 实际为在当前任务下添加子任务， 若子任务全部完成后，
进行后续处理

- 前加签 ： 子任务全部完成后， 回到加签任务继续审批
- 后加签 ： 子任务全部完成后， 回到加签任务之后继续审批， 加签任务视为审批通过
