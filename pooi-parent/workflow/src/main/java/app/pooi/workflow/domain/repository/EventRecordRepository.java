package app.pooi.workflow.domain.repository;

import app.pooi.workflow.domain.model.workflow.eventpush.EventRecord;

import java.util.Collection;

public interface EventRecordRepository {

    boolean saveAll(Collection<EventRecord> eventRecords, int batchSize);
}
