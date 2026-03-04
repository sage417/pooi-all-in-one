package app.pooi.workflow.application.service;

import app.pooi.workflow.application.converter.IamUserMapper;
import app.pooi.workflow.domain.repository.IamUserRepository;
import app.pooi.workflow.interfaces.rest.res.IamUserRes;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class IamUserAppService {

    private final IamUserMapper iamUserMapper;
    private final IamUserRepository iamUserRepository;

    public Optional<IamUserRes> queryUserByUsername(String username) {
        return iamUserRepository.findByUsername(username)
                .map(iamUserMapper::toRes);
    }
}
