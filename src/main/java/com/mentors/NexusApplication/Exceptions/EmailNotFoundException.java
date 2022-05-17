package com.mentors.NexusApplication.Exceptions;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EmailNotFoundException extends Exception {
    public EmailNotFoundException(String message) {
        super(message);
    }
}
