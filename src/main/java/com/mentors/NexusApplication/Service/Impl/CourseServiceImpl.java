package com.mentors.NexusApplication.Service.Impl;

import com.mentors.NexusApplication.Exceptions.CourseNotFoundException;
import com.mentors.NexusApplication.Exceptions.ResourceNotFoundException;
import com.mentors.NexusApplication.Model.Course;
import com.mentors.NexusApplication.Repository.CourseCategoryRepository;
import com.mentors.NexusApplication.Repository.CourseRepository;
import com.mentors.NexusApplication.Repository.UserRepository;
import com.mentors.NexusApplication.Service.CourseService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;


import javax.transaction.Transactional;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static com.mentors.NexusApplication.Constants.FileConstant.COURSE_FOLDER;

@Service
@Transactional
@Qualifier("courseDetailService")
public class CourseServiceImpl implements CourseService {
    private static final Logger LOGGER = LoggerFactory.getLogger(CourseServiceImpl.class);

    private final CourseRepository courseRepository;
    private final UserRepository userRepository;
    private final CourseCategoryRepository courseCategoryRepository;

    public CourseServiceImpl(CourseRepository courseRepository, UserRepository userRepository,CourseCategoryRepository courseCategoryRepository) {
        this.courseRepository = courseRepository;
        this.userRepository = userRepository;
        this.courseCategoryRepository = courseCategoryRepository;
    }

    public List<Course> getAllCourses(){ return courseRepository.findAll(); }

    public List<Course> getAllPublishedCourses(){ return courseRepository.findByIsPublished(true); }

    @Override
    public List<Course> getAllCoursesByCategoryId(long courseCategoryId) throws ResourceNotFoundException {
       if(!courseCategoryRepository.existsById(courseCategoryId)){
           throw new ResourceNotFoundException("Course category with ID:" + courseCategoryId + " was not found!");
       }
       return courseRepository.findByCourseCategoryId(courseCategoryId);
    }

    @Override
    public List<Course> getAllCoursesByUserId(Long userId) throws ResourceNotFoundException {
        if(!userRepository.existsById(userId)){
            throw new ResourceNotFoundException("User with User Id:" + userId + " was not found!");
        }
        return courseRepository.findCoursesByEnrolledUsersId(userId);
    }

    //TODO Resolve how to pass optional values for Ids
    @Override
    public List<Course> getAllFilteredCourses(Long courseCategoryId, Long userId) throws ResourceNotFoundException {
        return null;
    }

    public Course findCourseById(Long id) throws CourseNotFoundException {
        Course course = courseRepository.findCourseById(id);
        if(course == null){
            throw new CourseNotFoundException("NotFound");
        }
        return course;
    }

    @Override
    public Course addNewCourse(String courseName, String courseDescription, Long courseOwnerId) throws IOException {
        Course course = new Course();
        UUID courseUUID = UUID.randomUUID();
        Path coursePath =  Paths.get(COURSE_FOLDER + courseUUID);

        course.setCourseName(courseName);
        course.setCourseDescription(courseDescription);
        course.setCourseOwnerId(courseOwnerId);
        course.setCourseUUID(courseUUID);
        course.setCourseCreated(new Date());
        course.setCourseUpdated(new Date());
        course.setPrivate(false);
        course.setPublished(false);

        courseRepository.save(course);
        LOGGER.info("Created new course with id " + courseUUID);
        if(!Files.exists(coursePath)){
            Files.createDirectories(coursePath);
            LOGGER.info("Directory created " + coursePath);
        }
        return course;
    }

    public Course updateCourse(Long id, String courseName, String courseDescription, Long courseOwnerId,Date coursePublishedDate, Boolean courseIsPrivate, Boolean courseIsPublished) throws CourseNotFoundException {
        Course course = validateIfCourseExistsById(id);

        Boolean resultingPublishedState = validateCoursePublishedState(coursePublishedDate,courseIsPublished);
        course.setCourseName(courseName);
        course.setCourseDescription(courseDescription);
        course.setCourseOwnerId(courseOwnerId);
        course.setCoursePublishDate(coursePublishedDate);
        course.setPrivate(courseIsPrivate);
        course.setPublished(resultingPublishedState);
        course.setCourseUpdated(new Date());

        courseRepository.save(course);
        return course;
    }

    public Boolean deleteCourseById(Long id){
        courseRepository.deleteById(id);
        return true;
    }



    private Course validateIfCourseExistsById(Long id) throws CourseNotFoundException {
        Course courseById = findCourseById(id);
        if( courseById == null ){
            throw new CourseNotFoundException("No course with id found");
        }
        return courseById;
    }

    public void updateAllCoursesPublishedState(){
        List<Course> courses = getAllCourses();
        for (Course course : courses){
            if (course.getCoursePublishDate()==null || course.getPublished()){
                LOGGER.info("Skipping course " + course.getCourseName() + " (ID) " + course.getCourseUUID() + " published date not set or already published course");
                continue;
            }
            if (course.getCoursePublishDate().before(new Date())){
                course.setPublished(true);
                LOGGER.info("Updated status to PUBLISHED for course " + course.getCourseName() + " " + course.getCourseUUID());
            } else {
                LOGGER.info("Course " + course.getCourseName() + " remains unpublished");
            }
        }
    }

    private Boolean validateCoursePublishedState(Date coursePublishedDate, Boolean isPublished){
        if(coursePublishedDate.after(new Date()) && isPublished.equals(true)){
            LOGGER.info("CANNOT PUBLISH COURSE IF PUBLISHED DATE IS IN THE FUTURE");
            return false;
        }
        if(coursePublishedDate.before(new Date()) && isPublished.equals(false)){
            return false;
        }
        return true;
    }

}
