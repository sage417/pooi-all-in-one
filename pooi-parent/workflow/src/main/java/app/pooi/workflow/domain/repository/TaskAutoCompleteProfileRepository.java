package app.pooi.workflow.domain.repository;

import app.pooi.workflow.domain.model.workflow.autocomplete.TaskAutoCompleteProfile;

import java.util.Optional;

public interface TaskAutoCompleteProfileRepository {

    boolean save(TaskAutoCompleteProfile taskAutoCompleteProfile);

    Optional<TaskAutoCompleteProfile> queryByDefinitionKey(String definitionKey);
}
