package app.pooi.workflow.application.converter;

import app.pooi.workflow.domain.model.IamUser;
import app.pooi.workflow.interfaces.rest.res.IamUserRes;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface IamUserMapper {

    IamUserRes toRes(IamUser user);
}
