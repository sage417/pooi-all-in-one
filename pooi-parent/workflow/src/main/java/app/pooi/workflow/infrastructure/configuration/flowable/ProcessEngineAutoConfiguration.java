/* Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package app.pooi.workflow.infrastructure.configuration.flowable;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.flowable.common.engine.api.async.AsyncTaskExecutor;
import org.flowable.common.engine.api.scope.ScopeTypes;
import org.flowable.common.engine.impl.cfg.IdGenerator;
import org.flowable.common.engine.impl.cfg.multitenant.TenantInfoHolder;
import org.flowable.common.engine.impl.persistence.StrongUuidGenerator;
import org.flowable.common.spring.AutoDeploymentStrategy;
import org.flowable.common.spring.CommonAutoDeploymentProperties;
import org.flowable.common.spring.async.SpringAsyncTaskExecutor;
import org.flowable.engine.ProcessEngine;
import org.flowable.http.common.api.client.FlowableHttpClient;
import org.flowable.job.service.impl.asyncexecutor.AsyncExecutor;
import org.flowable.spring.SpringProcessEngineConfiguration;
import org.flowable.spring.boot.*;
import org.flowable.spring.boot.app.AppEngineAutoConfiguration;
import org.flowable.spring.boot.app.AppEngineServicesAutoConfiguration;
import org.flowable.spring.boot.app.FlowableAppProperties;
import org.flowable.spring.boot.condition.ConditionalOnProcessEngine;
import org.flowable.spring.boot.eventregistry.FlowableEventRegistryProperties;
import org.flowable.spring.boot.idm.FlowableIdmProperties;
import org.flowable.spring.boot.process.FlowableProcessProperties;
import org.flowable.spring.boot.process.Process;
import org.flowable.spring.boot.process.ProcessAsync;
import org.flowable.spring.boot.process.ProcessAsyncHistory;
import org.flowable.spring.configurator.DefaultAutoDeploymentStrategy;
import org.flowable.spring.configurator.ResourceParentFolderAutoDeploymentStrategy;
import org.flowable.spring.configurator.SingleResourceAutoDeploymentStrategy;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.task.TaskExecutionAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.Resource;
import org.springframework.transaction.PlatformTransactionManager;

import javax.sql.DataSource;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;


/**
 * Provides sane definitions for the various beans required to be productive with Flowable in Spring.
 *
 * @author Josh Long
 * @author Filip Hrisafov
 * @author Javier Casal
 * @author Joram Barrez
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProcessEngine
@EnableConfigurationProperties({
        FlowableAutoDeploymentProperties.class,
        FlowableProperties.class,
        FlowableMailProperties.class,
        FlowableHttpProperties.class,
        FlowableProcessProperties.class,
        FlowableAppProperties.class,
        FlowableIdmProperties.class,
        FlowableEventRegistryProperties.class
})
@AutoConfigureAfter(value = {
        FlowableJpaAutoConfiguration.class,
        AppEngineAutoConfiguration.class,
        TaskExecutionAutoConfiguration.class
})
@AutoConfigureBefore(value = {
        AppEngineServicesAutoConfiguration.class,
})
@Import({
        FlowableJobConfiguration.class
})
public class ProcessEngineAutoConfiguration extends org.flowable.spring.boot.ProcessEngineAutoConfiguration {

    public ProcessEngineAutoConfiguration(FlowableProperties flowableProperties, FlowableProcessProperties processProperties,
                                          FlowableAppProperties appProperties, FlowableIdmProperties idmProperties,
                                          FlowableEventRegistryProperties eventProperties, FlowableMailProperties mailProperties,
                                          FlowableHttpProperties httpProperties, FlowableAutoDeploymentProperties autoDeploymentProperties) {

        super(flowableProperties, processProperties, appProperties, idmProperties, eventProperties, mailProperties, httpProperties, autoDeploymentProperties);
    }

    @Bean
    public SpringProcessEngineConfiguration springProcessEngineConfiguration(DataSource dataSource, PlatformTransactionManager platformTransactionManager,
                                                                             ObjectProvider<ObjectMapper> objectMapperProvider,
                                                                             @Process ObjectProvider<IdGenerator> processIdGenerator,
                                                                             ObjectProvider<IdGenerator> globalIdGenerator,
                                                                             @ProcessAsync ObjectProvider<AsyncExecutor> asyncExecutorProvider,
                                                                             @Qualifier("applicationTaskExecutor") ObjectProvider<org.springframework.core.task.AsyncTaskExecutor> applicationTaskExecutorProvider,
                                                                             @ProcessAsyncHistory ObjectProvider<AsyncExecutor> asyncHistoryExecutorProvider,
                                                                             ObjectProvider<org.springframework.core.task.AsyncTaskExecutor> taskExecutor,
                                                                             @Process ObjectProvider<org.springframework.core.task.AsyncTaskExecutor> processTaskExecutor,
                                                                             @Qualifier("flowableAsyncTaskInvokerTaskExecutor") ObjectProvider<AsyncTaskExecutor> asyncTaskInvokerTaskExecutor,
                                                                             ObjectProvider<FlowableHttpClient> flowableHttpClient,
                                                                             ObjectProvider<AutoDeploymentStrategy<ProcessEngine>> processEngineAutoDeploymentStrategies,
                                                                             ObjectProvider<TenantInfoHolder> tenantInfoHolder) throws IOException {

        SpringProcessEngineConfiguration conf = tenantInfoHolder.getIfUnique() != null ?
                new MultiSchemaMultiTenantProcessEngineConfiguration(tenantInfoHolder.getIfUnique()) :
                new SpringProcessEngineConfiguration();

        List<Resource> resources = this.discoverDeploymentResources(
                flowableProperties.getProcessDefinitionLocationPrefix(),
                flowableProperties.getProcessDefinitionLocationSuffixes(),
                flowableProperties.isCheckProcessDefinitions()
        );

        if (resources != null && !resources.isEmpty()) {
            conf.setDeploymentResources(resources.toArray(new Resource[0]));
            conf.setDeploymentName(flowableProperties.getDeploymentName());
        }

        AsyncExecutor springAsyncExecutor = asyncExecutorProvider.getIfUnique();
        if (springAsyncExecutor != null) {
            conf.setAsyncExecutor(springAsyncExecutor);
        }

        org.springframework.core.task.AsyncTaskExecutor asyncTaskExecutor = getIfAvailable(processTaskExecutor, taskExecutor);
        if (asyncTaskExecutor == null) {
            // Get the applicationTaskExecutor
            asyncTaskExecutor = applicationTaskExecutorProvider.getObject();
        }
        if (asyncTaskExecutor != null) {
            // The task executors are shared
            org.flowable.common.engine.api.async.AsyncTaskExecutor flowableTaskExecutor = new SpringAsyncTaskExecutor(asyncTaskExecutor);
            conf.setAsyncTaskExecutor(flowableTaskExecutor);
            conf.setAsyncHistoryTaskExecutor(flowableTaskExecutor);
        }

        AsyncExecutor springAsyncHistoryExecutor = asyncHistoryExecutorProvider.getIfUnique();
        if (springAsyncHistoryExecutor != null) {
            conf.setAsyncHistoryEnabled(true);
            conf.setAsyncHistoryExecutor(springAsyncHistoryExecutor);
        }

        asyncTaskInvokerTaskExecutor.ifAvailable(conf::setAsyncTaskInvokerTaskExecutor);

        objectMapperProvider.ifAvailable(conf::setObjectMapper);
        configureSpringEngine(conf, platformTransactionManager);
        configureEngine(conf, dataSource);

        conf.setDeploymentName(defaultText(flowableProperties.getDeploymentName(), conf.getDeploymentName()));

        conf.setDisableIdmEngine(!(flowableProperties.isDbIdentityUsed() && idmProperties.isEnabled()));
        conf.setDisableEventRegistry(!eventProperties.isEnabled());

        conf.setAsyncExecutorActivate(flowableProperties.isAsyncExecutorActivate());
        conf.setAsyncHistoryExecutorActivate(flowableProperties.isAsyncHistoryExecutorActivate());

        conf.setDeploymentName(defaultText(flowableProperties.getDeploymentName(), conf.getDeploymentName()));

        conf.setDisableIdmEngine(!(flowableProperties.isDbIdentityUsed() && idmProperties.isEnabled()));
        conf.setDisableEventRegistry(!eventProperties.isEnabled());

        conf.setAsyncExecutorActivate(flowableProperties.isAsyncExecutorActivate());
        conf.setAsyncHistoryExecutorActivate(flowableProperties.isAsyncHistoryExecutorActivate());

        conf.setMailServerHost(mailProperties.getHost());
        conf.setMailServerPort(mailProperties.getPort());
        conf.setMailServerSSLPort(mailProperties.getSSLPort());
        conf.setMailServerUsername(mailProperties.getUsername());
        conf.setMailServerPassword(mailProperties.getPassword());
        conf.setMailServerDefaultFrom(mailProperties.getDefaultFrom());
        conf.setMailServerForceTo(mailProperties.getForceTo());
        conf.setMailServerUseSSL(mailProperties.isUseSsl());
        conf.setMailServerUseTLS(mailProperties.isUseTls());
        conf.setMailServerDefaultCharset(mailProperties.getDefaultCharset());

        conf.getHttpClientConfig().setUseSystemProperties(httpProperties.isUseSystemProperties());
        conf.getHttpClientConfig().setConnectionRequestTimeout(httpProperties.getConnectionRequestTimeout());
        conf.getHttpClientConfig().setConnectTimeout(httpProperties.getConnectTimeout());
        conf.getHttpClientConfig().setDisableCertVerify(httpProperties.isDisableCertVerify());
        conf.getHttpClientConfig().setRequestRetryLimit(httpProperties.getRequestRetryLimit());
        conf.getHttpClientConfig().setSocketTimeout(httpProperties.getSocketTimeout());
        conf.getHttpClientConfig().setHttpClient(flowableHttpClient.getIfAvailable());

        conf.setEnableProcessDefinitionHistoryLevel(processProperties.isEnableProcessDefinitionHistoryLevel());
        conf.setProcessDefinitionCacheLimit(processProperties.getDefinitionCacheLimit());
        conf.setEnableSafeBpmnXml(processProperties.isEnableSafeXml());
        conf.setEventRegistryStartProcessInstanceAsync(processProperties.isEventRegistryStartProcessInstanceAsync());
        conf.setEventRegistryUniqueProcessInstanceCheckWithLock(processProperties.isEventRegistryUniqueProcessInstanceCheckWithLock());
        conf.setEventRegistryUniqueProcessInstanceStartLockTime(processProperties.getEventRegistryUniqueProcessInstanceStartLockTime());

        conf.setHistoryLevel(flowableProperties.getHistoryLevel());

        conf.setActivityFontName(flowableProperties.getActivityFontName());
        conf.setAnnotationFontName(flowableProperties.getAnnotationFontName());
        conf.setLabelFontName(flowableProperties.getLabelFontName());

        conf.setFormFieldValidationEnabled(flowableProperties.isFormFieldValidationEnabled());

        conf.setEnableHistoryCleaning(flowableProperties.isEnableHistoryCleaning());
        conf.setHistoryCleaningTimeCycleConfig(flowableProperties.getHistoryCleaningCycle());
        conf.setCleanInstancesEndedAfter(flowableProperties.getHistoryCleaningAfter());
        conf.setCleanInstancesBatchSize(flowableProperties.getHistoryCleaningBatchSize());

        IdGenerator idGenerator = getIfAvailable(processIdGenerator, globalIdGenerator);
        if (idGenerator == null) {
            idGenerator = new StrongUuidGenerator();
        }
        conf.setIdGenerator(idGenerator);

        List<AutoDeploymentStrategy<ProcessEngine>> deploymentStrategies = processEngineAutoDeploymentStrategies.orderedStream().collect(Collectors.toList());
        CommonAutoDeploymentProperties deploymentProperties = this.autoDeploymentProperties.deploymentPropertiesForEngine(ScopeTypes.BPMN);

        // Always add the out of the box auto deployment strategies as last
        deploymentStrategies.add(new DefaultAutoDeploymentStrategy(deploymentProperties));
        deploymentStrategies.add(new SingleResourceAutoDeploymentStrategy(deploymentProperties));
        deploymentStrategies.add(new ResourceParentFolderAutoDeploymentStrategy(deploymentProperties));
        conf.setDeploymentStrategies(deploymentStrategies);

        if (tenantInfoHolder.getIfAvailable() != null) {
            MultiTenantDefaultAutoDeploymentStrategy multiTenantDefaultAutoDeploymentStrategy = new MultiTenantDefaultAutoDeploymentStrategy();
            deploymentStrategies.add(multiTenantDefaultAutoDeploymentStrategy);
            conf.setDeploymentMode(multiTenantDefaultAutoDeploymentStrategy.getDeploymentMode());
        }

        return conf;
    }

}
