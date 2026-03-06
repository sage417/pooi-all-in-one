package app.pooi.workflow.infrastructure.configuration.flowable.engine;

import app.pooi.basic.util.SpringContextUtil;
import app.pooi.tenant.multitenancy.ApplicationInfoHolder;
import app.pooi.workflow.application.eventpush.EventPushApplication;
import app.pooi.workflow.domain.model.workflow.eventpush.EventRecord;
import app.pooi.workflow.domain.repository.EventRecordRepository;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ListMultimap;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomUtils;
import org.redisson.api.RFuture;
import org.redisson.api.RLock;
import org.redisson.api.RedissonClient;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.List;
import java.util.Objects;
import java.util.StringJoiner;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.stream.Collectors;

@Slf4j
public class EventListenerTransactionSynchronization implements TransactionSynchronization {
    private static final ThreadLocal<ListMultimap<String, Supplier<EventRecord>>> TL_EVENT_RECORD_SUPPLIER =
            ThreadLocal.withInitial(ArrayListMultimap::create);

    private final String procInstId;

    private final RedissonClient redissonClient;

    private final ApplicationInfoHolder applicationInfoHolder;

    private final EventRecordRepository eventRecordRepository;

    private final EventPushApplication eventPushApplication;

    public static void registerOnce(String procInstId, Supplier<EventRecord> recordSupplier) {
        ListMultimap<String, Supplier<EventRecord>> eventRecords = TL_EVENT_RECORD_SUPPLIER.get();

        if (eventRecords.get(procInstId).isEmpty()) {
            TransactionSynchronizationManager.registerSynchronization(new EventListenerTransactionSynchronization(procInstId));
        }
        eventRecords.put(procInstId, recordSupplier);
    }

    private EventListenerTransactionSynchronization(String procInstId) {
        this.procInstId = procInstId;
        this.redissonClient = SpringContextUtil.getBean(RedissonClient.class);
        this.applicationInfoHolder = SpringContextUtil.getBean(ApplicationInfoHolder.class);
        this.eventRecordRepository = SpringContextUtil.getBean(EventRecordRepository.class);
        this.eventPushApplication = SpringContextUtil.getBean(EventPushApplication.class);
//        TL_EVENT_RECORD_SUPPLIER.get().put(procInstId, recordDOSupplier);
    }

    @Override
    public void afterCommit() {
        List<Supplier<EventRecord>> runnableList = TL_EVENT_RECORD_SUPPLIER.get().removeAll(this.procInstId);
        if (runnableList.isEmpty()) {
            return;
        }
        // 记录event record
        List<EventRecord> eventRecordDOS = prepareEventDOs(runnableList, this.procInstId);
        // not actually multi value insert
        this.eventRecordRepository.saveAll(eventRecordDOS, 100);

        String applicationCode = this.applicationInfoHolder.getApplicationCode();
        RLock fairLock = redissonClient.getFairLock(new StringJoiner(":").add("workflow").add("app").add(applicationCode)
                .add("EP").add("pId").add(this.procInstId).add("fl").toString());
        long tId = RandomUtils.nextLong();
        RFuture<Boolean> lockAsync = fairLock.tryLockAsync(240L, 180L, TimeUnit.SECONDS, tId);
        log.info("lockAsync lock: {}, tId: {}", fairLock.getName(), tId);

        eventPushApplication.asyncExecute(fairLock, lockAsync, tId, eventRecordDOS);
    }


    private static List<EventRecord> prepareEventDOs(List<Supplier<EventRecord>> suppliers, String procInstId) {
        return suppliers.stream()
                .map(s -> {
                    try {
                        return s.get();
                    } catch (Exception e) {
                        log.error("procInst task error, proInstId:{}", procInstId, e);
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    @Override
    public void afterCompletion(int status) {
        ListMultimap<String, ?> runnableListMultimap = TL_EVENT_RECORD_SUPPLIER.get();
        if (!runnableListMultimap.isEmpty()) {
            log.warn("TransactionSynchronization status: {}, clear procInst tasks: {}", status, runnableListMultimap.keySet());
            runnableListMultimap.clear();
        }
    }
}
