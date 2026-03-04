package app.pooi.workflow.interfaces.rest.res;

import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class IamUserRes {
    private String id;
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private boolean emailVerified;
    private Map<String, List<String>> attributes;
}
