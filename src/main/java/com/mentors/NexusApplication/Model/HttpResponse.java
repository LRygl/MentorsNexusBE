package com.mentors.NexusApplication.Model;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.experimental.SuperBuilder;
import org.springframework.http.HttpStatus;

import java.util.Date;
import java.util.Map;

@Data
@SuperBuilder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class HttpResponse {
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-DD-dd hh:mm:ss", timezone = "Europe/Prague")
    private Date httpTimestamp;
    private int httpStatusCode;
    private HttpStatus httpStatus;
    private String httpStatusReason;
    private String httpStatusMessage;
    private String httpDeveloperMessage;
    private String httpPath;
    private Map<?,?> httpResponseData;

    public HttpResponse() {
    }

    public HttpResponse(Date httpTimestamp, int httpStatusCode, HttpStatus httpStatus, String httpStatusReason, String httpStatusMessage, String httpDeveloperMessage, Map<?, ?> httpResponseData) {
        this.httpTimestamp = httpTimestamp;
        this.httpStatusCode = httpStatusCode;
        this.httpStatus = httpStatus;
        this.httpStatusReason = httpStatusReason;
        this.httpStatusMessage = httpStatusMessage;
        this.httpDeveloperMessage = httpDeveloperMessage;
        this.httpResponseData = httpResponseData;
    }

    public Date getHttpTimestamp() {
        return httpTimestamp;
    }

    public void setHttpTimestamp(Date httpTimestamp) {
        this.httpTimestamp = httpTimestamp;
    }

    public int getHttpStatusCode() {
        return httpStatusCode;
    }

    public void setHttpStatusCode(int httpStatusCode) {
        this.httpStatusCode = httpStatusCode;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }

    public void setHttpStatus(HttpStatus httpStatus) {
        this.httpStatus = httpStatus;
    }

    public String getHttpStatusReason() {
        return httpStatusReason;
    }

    public void setHttpStatusReason(String httpStatusReason) {
        this.httpStatusReason = httpStatusReason;
    }

    public String getHttpStatusMessage() {
        return httpStatusMessage;
    }

    public void setHttpStatusMessage(String httpStatusMessage) {
        this.httpStatusMessage = httpStatusMessage;
    }

    public String getHttpDeveloperMessage() {
        return httpDeveloperMessage;
    }

    public void setHttpDeveloperMessage(String httpDeveloperMessage) {
        this.httpDeveloperMessage = httpDeveloperMessage;
    }

    public Map<?, ?> getHttpResponseData() {
        return httpResponseData;
    }

    public void setHttpResponseData(Map<?, ?> httpResponseData) {
        this.httpResponseData = httpResponseData;
    }
}
