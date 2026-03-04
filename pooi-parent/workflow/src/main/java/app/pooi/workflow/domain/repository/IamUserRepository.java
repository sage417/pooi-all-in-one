package app.pooi.workflow.domain.repository;

import app.pooi.workflow.domain.model.IamUser;

import java.util.List;
import java.util.Optional;


public interface IamUserRepository {

    Optional<IamUser> findByUsername(String username);


    List<IamUser> findAll(int first, int max);


    Optional<IamUser> findById(String userId);
}