package com.mentors.NexusApplication.Jobs;

import com.mentors.NexusApplication.Service.CourseService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;


@Component
public class CoursePublishedJob {
    private static final Logger LOGGER = LoggerFactory.getLogger(CoursePublishedJob.class);

    public CoursePublishedJob(CourseService courseService) {
        this.courseService = courseService;
    }

    private CourseService courseService;

    @Scheduled(cron = "${cron.coursePublishedJob.value}")
    public void updateCoursePublishedState() throws InterruptedException{

        Instant jobStart = Instant.now();
        LOGGER.info("Starting execution of job " + CoursePublishedJob.class);

        courseService.updateAllCoursesPublishedState();
        Instant jobEnd = Instant.now();
        Duration duration = Duration.between(jobStart,jobEnd);
        LOGGER.info("Stopping execution of job " + CoursePublishedJob.class + " Job executed in " + duration);
    }
}
