package app.pooi.workflow.domain.repository;

import app.pooi.workflow.domain.model.IAMUser;

import java.util.List;
import java.util.Optional;


public interface IAMUserRepository {

    Optional<IAMUser> findByUsername(String username);


    List<IAMUser> findAll(int first, int max);


    Optional<IAMUser> findById(String userId);
}