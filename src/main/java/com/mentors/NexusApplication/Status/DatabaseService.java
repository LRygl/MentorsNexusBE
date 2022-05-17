package com.mentors.NexusApplication.Status;

import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

@Component
public class DatabaseService implements HealthIndicator {
    private final String DATABASE_SERVICE = "DatabaseService";

    @Override
    public Health health(){
        if(isDatabaseUp()){
            return Health.up().withDetail(DATABASE_SERVICE,"Service is running").build();
        }
        return Health.down().withDetail(DATABASE_SERVICE,"Service is not running").build();

    }

    private boolean isDatabaseUp(){
        return true;
    }
}
