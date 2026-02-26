//package app.pooi.workflow.infrastructure.configuration.flowable.modeler;
//
//import org.flowable.ui.common.tenant.TenantProvider;
//import org.flowable.ui.modeler.properties.FlowableModelerAppProperties;
//import org.flowable.ui.modeler.service.FlowableModelQueryService;
//import org.flowable.ui.modeler.service.ModelImageService;
//import org.flowable.ui.modeler.service.ModelServiceImpl;
//import org.flowable.ui.modeler.serviceapi.ModelService;
//import org.springframework.boot.context.properties.EnableConfigurationProperties;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.ComponentScan;
//import org.springframework.context.annotation.Configuration;
//
/// **
// * @author sage417
// */
//@Configuration
////@ImportAutoConfiguration(ModelerDatabaseConfiguration.class)
//@EnableConfigurationProperties(FlowableModelerAppProperties.class)
//@ComponentScan(basePackages = {
//        "org.flowable.ui.modeler.repository",
//        "org.flowable.ui.common.repository"
//})
//class ApplicationConfiguration {
//
//    @Bean
//    public TenantProvider mockTenantProvider() {
//        return new MockTenantProvider();
//    }
//
//    // The services are shared between the api and app rest modules
//    @Bean
//    public ModelService modelerModelService() {
//        return new ModelServiceImpl();
//    }
//
//    @Bean
//    public ModelImageService modelerModelImageService() {
//        return new ModelImageService();
//    }
//
//    @Bean
//    public FlowableModelQueryService modelerModelQueryService() {
//        return new FlowableModelQueryService();
//    }
//
//}
