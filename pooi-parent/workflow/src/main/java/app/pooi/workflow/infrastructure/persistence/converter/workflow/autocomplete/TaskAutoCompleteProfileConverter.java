package app.pooi.workflow.infrastructure.persistence.converter.workflow.autocomplete;


import app.pooi.workflow.domain.model.workflow.autocomplete.TaskAutoCompleteProfile;
import app.pooi.workflow.infrastructure.persistence.entity.workflow.autocomplete.TaskAutoCompleteProfileEntity;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface TaskAutoCompleteProfileConverter {

    TaskAutoCompleteProfileEntity toEntity(final TaskAutoCompleteProfile comment);

    TaskAutoCompleteProfile toModel(TaskAutoCompleteProfileEntity entity);

}
