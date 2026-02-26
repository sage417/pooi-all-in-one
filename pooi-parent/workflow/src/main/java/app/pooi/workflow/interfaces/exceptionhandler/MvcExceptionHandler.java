package app.pooi.workflow.interfaces.exceptionhandler;

import app.pooi.basic.expection.BusinessException;
import app.pooi.basic.rest.CommonResult;
import app.pooi.basic.rest.resp.ValidationFieldError;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import javax.annotation.Resource;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

@ControllerAdvice
public class MvcExceptionHandler extends ResponseEntityExceptionHandler {

    @Resource
    private MessageSource messageSource;

    /**
     * 处理流程业务异常
     */
    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<CommonResult<Void>> handleProcessBizException(
            BusinessException ex,
            HttpServletRequest request,
            Locale locale
    ) {
        String errorMessage = messageSource.getMessage(
                ex.getMessageCode(),
                ex.getArgs(),
                ex.getMessageCode(), // default message when missing
                locale
        );

        CommonResult<Void> body = CommonResult.fail("1001", errorMessage, request.getRequestURI(), null);

        return ResponseEntity.badRequest().body(body);
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
                                                                  HttpHeaders headers, HttpStatusCode status,
                                                                  WebRequest request) {
        String path = "";
        if (request instanceof ServletWebRequest servletWebRequest) {
            path = servletWebRequest.getRequest().getRequestURI();
        }

        List<ValidationFieldError> fieldErrors = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(error -> new ValidationFieldError(
                        error.getField(),
                        error.getDefaultMessage()
                ))
                .collect(Collectors.toList());

        CommonResult<List<ValidationFieldError>> body = CommonResult.fail("1001", null, path, fieldErrors);

        return handleExceptionInternal(ex, body, headers, status, request);
    }
}
