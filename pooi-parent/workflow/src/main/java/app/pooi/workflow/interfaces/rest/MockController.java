package app.pooi.workflow.interfaces.rest;

import app.pooi.basic.expection.BusinessException;
import app.pooi.basic.rest.CommonResult;
import app.pooi.rpc.workflow.stubs.HelloWorldRequest;
import app.pooi.rpc.workflow.stubs.HelloWorldResponse;
import app.pooi.tenant.multitenancy.ApplicationInfo;
import app.pooi.tenant.multitenancy.ApplicationInfoHolder;
import app.pooi.workflow.application.eventpush.GenericGrpcInvoker;
import app.pooi.workflow.application.service.ProcessInstanceStartAppService;
import app.pooi.workflow.infrastructure.messaging.event.EventPayload;
import app.pooi.workflow.interfaces.rest.req.QueryUserReq;
import jakarta.validation.Valid;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.util.List;

@RequestMapping("/mock")
@RestController
public class MockController {

    @Resource
    private ProcessInstanceStartAppService processInstanceStartApplication;

    @Resource
    private ApplicationInfoHolder applicationInfoHolder;

//    @Resource
//    private ProcessDefinitionDeployApplication processDefinitionDeployApplication;

    @Resource
    private GenericGrpcInvoker genericGrpcInvoker;

    @Resource
    private DiscoveryClient discoveryClient;

    @GetMapping("/test-discovery")
    public List<ServiceInstance> test() {
        return discoveryClient.getInstances("pooi-workflow-core");
    }


    @GetMapping("/say")
    public CommonResult<String> sayHelloWorld() {
        HelloWorldResponse response = genericGrpcInvoker.unaryCall("discovery:///pooi-workflow-core",
                "app.pooi.rpc.workflow.HelloWorldService", "SayHello", HelloWorldRequest.newBuilder()
                        .setName("your name")
                        .build());
        return CommonResult.success(response.getGreeting());
    }


    @GetMapping("/start")
    public CommonResult<Void> start() {
        this.applicationInfoHolder.setApplicationInfo(new ApplicationInfo().setApplicationCode("app1"));
//        processDefinitionDeployApplication.deployResource("processes/article-workflow.bpmn20.xml", "articleReview", "test-process");
        this.processInstanceStartApplication.start("articleReview", 1, "", "", null, "starter");
        return CommonResult.success(null);
    }

    @PostMapping("/event")
    public CommonResult<Void> processEvent(@RequestBody EventPayload eventPayload) {
        return CommonResult.success(null);
    }

    @GetMapping("/error")
    public CommonResult<Void> bizErr() {
        throw new BusinessException("error.process.definition.not_found", "abc", 1);
    }

    @PostMapping("/validation")
    public CommonResult<Void> validation(@RequestBody @Valid QueryUserReq queryUserReq) {
        return CommonResult.success(null);
    }
}
