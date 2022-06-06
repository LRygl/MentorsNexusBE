package com.mentors.NexusApplication.Service;

import com.mentors.NexusApplication.Exceptions.CourseCategoryNotFoundException;
import com.mentors.NexusApplication.Exceptions.ResourceNotFoundException;
import com.mentors.NexusApplication.Model.CourseCategory;

import java.util.List;


public interface CourseCategoryService {
    List<CourseCategory> getAllCourseCategories();
    CourseCategory getCourseCategoryById(Long courseCategoryId);
    CourseCategory addNewCourseCategory(String courseCategoryName, String courseCategoryDescription,String courseCategoryCode, Boolean courseCategoryIsActive);
    CourseCategory deactivateCourseCategoryById(Long courseCategoryId) throws  CourseCategoryNotFoundException;
    CourseCategory updateCourseCategory(Long id, String courseCategoryName, String courseCategoryDescription, Boolean courseCategoryActive) throws CourseCategoryNotFoundException;
    CourseCategory addCourseCagoryToCourse(Long courseId, Long courseCategoryId) throws ResourceNotFoundException;
    void deleteCourseCategoryById(Long courseCategoryId);

}
