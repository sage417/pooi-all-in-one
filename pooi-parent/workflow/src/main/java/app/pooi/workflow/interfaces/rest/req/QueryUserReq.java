package app.pooi.workflow.interfaces.rest.req;

import jakarta.validation.constraints.*;
import lombok.Data;

@Data
public class QueryUserReq {

    @NotBlank(message = "用户名不能为空")
    @Size(min = 2, max = 10, message = "用户名长度需在2-10之间")
    private String username;

    @NotNull(message = "年龄不能为空")
    @Min(value = 18, message = "年龄必须大于18岁")
    private Integer age;

    @Email(message = "邮箱格式不正确")
    private String email;
}
