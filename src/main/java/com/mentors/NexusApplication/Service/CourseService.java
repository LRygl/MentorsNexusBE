package com.mentors.NexusApplication.Service;

import com.mentors.NexusApplication.Exceptions.CourseNotFoundException;
import com.mentors.NexusApplication.Exceptions.ResourceNotFoundException;
import com.mentors.NexusApplication.Model.Course;

import java.io.IOException;
import java.util.Date;
import java.util.List;

public interface CourseService {
    List<Course> getAllCourses();
    List<Course> getAllPublishedCourses();
    //List<Course> getAllCoursesByUserId(Long userId);
    List<Course> getAllCoursesByCategoryId(long courseCategoryId) throws ResourceNotFoundException;
    List<Course> getAllCoursesByUserId(Long userId) throws ResourceNotFoundException;
    void updateAllCoursesPublishedState();
    Course updateCourse(Long id, String courseName, String courseDescription, Long courseOwnerId, Date coursePublishedDate, Boolean courseIsPrivate, Boolean courseIsPublished) throws CourseNotFoundException;
    Course addNewCourse(String courseName, String courseDescription, Long courseOwnerId) throws IOException;
    Course findCourseById(Long id) throws CourseNotFoundException;
    Boolean deleteCourseById(Long id);


    List<Course> getAllFilteredCourses(Long courseCategoryId, Long userId) throws ResourceNotFoundException;
}
