package com.mentors.NexusApplication.Exceptions;

import com.auth0.jwt.exceptions.TokenExpiredException;
import com.mentors.NexusApplication.Model.HttpResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.persistence.NoResultException;
import java.io.IOException;
import java.util.Date;
import java.util.Objects;

import static com.mentors.NexusApplication.Constants.ExceptionImplementationConstant.*;

@RestControllerAdvice
public class ExceptionHandling implements ErrorController {

    private final Logger LOGGER = LoggerFactory.getLogger(getClass());

    private ResponseEntity<HttpResponse> createHttpResponse(HttpStatus httpStatus, String httpStatusMessage) {
        return ResponseEntity
                .status(HttpStatus.resolve(httpStatus.value()))
                .body(HttpResponse.builder()
                        .httpStatus(httpStatus)
                        .httpStatusCode(httpStatus.value())
                        .httpTimestamp(new Date(System.currentTimeMillis()))
                        .httpStatusMessage(httpStatusMessage)
                        .httpDeveloperMessage("Oops")
                        .httpStatusReason("test")
                        .build()
        );
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<HttpResponse> ResourceNotFoundException(){
        return createHttpResponse(HttpStatus.NOT_FOUND,"RESOURCE WAS NOT FOUND");
    }

    @ExceptionHandler(CourseCategoryNotFoundException.class)
    public ResponseEntity<HttpResponse> CourseCategoryNotFoundException(){
        return createHttpResponse(HttpStatus.NOT_FOUND,"COURSE CATEGORY WAS NOT FOUND");
    }

    @ExceptionHandler(CourseNotFoundException.class)
    public ResponseEntity<HttpResponse> CourseNotFoundException(){
        return createHttpResponse(HttpStatus.NOT_FOUND,"COURSE WAS NOT FOUND");
    }

    @ExceptionHandler(PasswordResetException.class)
    public ResponseEntity<HttpResponse> passwordResetException(){
        return createHttpResponse(HttpStatus.BAD_REQUEST,PASSWORD_RESET_NOT_POSSIBLE_NO_MATCH);
    }

    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<HttpResponse> accountDisabledException(){
        return createHttpResponse(HttpStatus.BAD_REQUEST, ACCOUNT_DISABLED);
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<HttpResponse> badCredentialsException(){
        return createHttpResponse(HttpStatus.UNAUTHORIZED, INCORRECT_CREDENTIALS);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<HttpResponse> accessDeniedException(){
        return createHttpResponse(HttpStatus.FORBIDDEN, NOT_ENOUGH_PERMISSION);
    }

    @ExceptionHandler(LockedException.class)
    public ResponseEntity<HttpResponse> lockedException(){
        return createHttpResponse(HttpStatus.UNAUTHORIZED, ACCOUNT_LOCKED);
    }

    @ExceptionHandler(TokenExpiredException.class)
    public ResponseEntity<HttpResponse> tokenExpiredException(TokenExpiredException exception){
        return createHttpResponse(HttpStatus.UNAUTHORIZED, exception.getMessage());
    }


    @ExceptionHandler(EmailExistsException.class)
    public ResponseEntity<HttpResponse> emailExistException(EmailExistsException exception){
        LOGGER.info(exception.getMessage() + " Returning response back to client: " + HttpStatus.BAD_REQUEST);
        return createHttpResponse(HttpStatus.BAD_REQUEST, exception.getMessage());
    }

    @ExceptionHandler(UsernameExistsException.class)
    public ResponseEntity<HttpResponse> usernameExistException(UsernameExistsException exception){
        LOGGER.info(exception.getMessage() + " Returning response back to client: " + HttpStatus.BAD_REQUEST);
        return createHttpResponse(HttpStatus.BAD_REQUEST, exception.getMessage());
    }

    @ExceptionHandler(EmailNotFoundException.class)
    public ResponseEntity<HttpResponse> emailNotFoundException(EmailNotFoundException exception){
        LOGGER.info(exception.getMessage() + " Returning response back to client: " + HttpStatus.BAD_REQUEST);
        return createHttpResponse(HttpStatus.BAD_REQUEST,exception.getMessage());
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<HttpResponse> userNotFoundException(UserNotFoundException exception){
        LOGGER.info(exception.getMessage() + " Returning response back to client: " + HttpStatus.BAD_REQUEST);
        return createHttpResponse(HttpStatus.BAD_REQUEST, exception.getMessage());
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<HttpResponse> methodNotSupportedException(HttpRequestMethodNotSupportedException exception){
        LOGGER.info(exception.getMessage() + " Returning response back to client: " + HttpStatus.METHOD_NOT_ALLOWED);
        HttpMethod supportedMethod = Objects.requireNonNull(exception.getSupportedHttpMethods()).iterator().next();
        return createHttpResponse(HttpStatus.METHOD_NOT_ALLOWED, String.format(METHOD_IS_NOT_ALLOWED, supportedMethod));
    }

// Exception handler
//    @ExceptionHandler(NoHandlerFoundException.class)
//    public ResponseEntity<HttpResponse> methodNotSupportedException(NoHandlerFoundException exception){
//        return createHttpResponse(HttpStatus.BAD_REQUEST, "This Page was not found");
//    }

    @ExceptionHandler(NoResultException.class)
    public ResponseEntity<HttpResponse> notFoundException(NoResultException exception){
        LOGGER.error(exception.getMessage());
        return createHttpResponse(HttpStatus.NOT_FOUND, exception.getMessage());
    }

    @ExceptionHandler(IOException.class)
    public ResponseEntity<HttpResponse> iOException(IOException exception){
        LOGGER.error(exception.getMessage());
        return createHttpResponse(HttpStatus.INTERNAL_SERVER_ERROR, ERROR_PROCESSING_FILE);
    }

    //GENERAL EXCEPTION
    @ExceptionHandler(Exception.class)
    public ResponseEntity<HttpResponse> internalServerErrorException(Exception exception){
        LOGGER.error(exception.getMessage());
        return createHttpResponse(HttpStatus.INTERNAL_SERVER_ERROR, INTERNAL_SERVER_ERROR_MSG);
    }

    @RequestMapping(ERROR_PATH)
    public ResponseEntity<HttpResponse> notFound404(){
        return createHttpResponse(HttpStatus.NOT_FOUND, "The page was not found - no mapping for this request url");
    }

}
