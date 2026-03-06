package app.pooi.workflow.domain.repository;

import app.pooi.workflow.domain.model.workflow.autocomplete.TaskAutoCompleteProfile;

import java.util.List;

public interface TaskAutoCompleteProfileRepository {

    boolean save(TaskAutoCompleteProfile taskAutoCompleteProfile);

    List<TaskAutoCompleteProfile> queryByDefinitionKey(String definitionKey);
}
