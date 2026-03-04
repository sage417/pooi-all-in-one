package app.pooi.workflow.interfaces.rest;

import app.pooi.workflow.application.service.IamUserAppService;
import app.pooi.workflow.interfaces.rest.res.IamUserRes;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/mock/api/v1/users")
@RequiredArgsConstructor
public class IamUserController {

    private final IamUserAppService iamUserAppService;

    @GetMapping("/username/{username}")
    public ResponseEntity<IamUserRes> getUserByUsername(@PathVariable String username) {
        Optional<IamUserRes> userDTO = iamUserAppService.queryUserByUsername(username);
        return userDTO.map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}
