package com.mentors.NexusApplication.Service.Impl;

import com.mentors.NexusApplication.Exceptions.CourseCategoryNotFoundException;
import com.mentors.NexusApplication.Exceptions.ResourceNotFoundException;
import com.mentors.NexusApplication.Model.CourseCategory;
import com.mentors.NexusApplication.Repository.CourseCategoryRepository;
import com.mentors.NexusApplication.Repository.CourseRepository;
import com.mentors.NexusApplication.Service.CourseCategoryService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.Date;
import java.util.List;

@Service
@Transactional
@Qualifier("courseCategoryDetailsService")
public class CourseCategoryServiceImpl implements CourseCategoryService {

    private final CourseCategoryRepository courseCategoryRepository;
    private final CourseRepository courseRepository;

    public CourseCategoryServiceImpl(CourseCategoryRepository courseCategoryRepository, CourseRepository courseRepository) {
        this.courseCategoryRepository = courseCategoryRepository;
        this.courseRepository = courseRepository;
    }

    public CourseCategory getCourseCategoryById(Long id){
        return courseCategoryRepository.findCourseCategoryById(id);
    }

    @Override
    public List<CourseCategory> getAllCourseCategories(){ return courseCategoryRepository.findAll(); }



    public CourseCategory addNewCourseCategory(String courseCategoryName, String courseCategoryDescription,String courseCategoryCode, Boolean courseCategoryIsActive){
        CourseCategory courseCategory = new CourseCategory();
        courseCategory.setCourseCategoryName(courseCategoryName);
        courseCategory.setCourseCategoryDescription(courseCategoryDescription);
        courseCategory.setCourseCategoryCode(courseCategoryCode.toUpperCase());
        courseCategory.setCourseCategoryActive(courseCategoryIsActive);
        courseCategory.setCourseCategoryCreatedDate(new Date());
        courseCategory.setCourseCategoryUpdatedDate(new Date());

        courseCategoryRepository.save(courseCategory);
        return courseCategory;
    }



    public CourseCategory updateCourseCategory(Long id, String courseCategoryName, String courseCategoryDescription, Boolean courseCategoryActive) throws CourseCategoryNotFoundException {
        CourseCategory courseCategory = validateIfCourseCategoryExistsById(id);

        courseCategory.setCourseCategoryName(courseCategoryName);
        courseCategory.setCourseCategoryDescription(courseCategoryDescription);
        courseCategory.setCourseCategoryActive(courseCategoryActive);

        courseCategory.setCourseCategoryUpdatedDate(new Date());
        return courseCategory;
    }
    //TODO Optimize
    @Override
    public CourseCategory addCourseCagoryToCourse(Long courseId, Long courseCategoryId) throws ResourceNotFoundException {
        CourseCategory courseCategory = courseCategoryRepository.findById(courseCategoryId).orElseThrow(()->new ResourceNotFoundException("not found"));
        return courseRepository.findById(courseId).map(
                course -> {
                    courseCategory.addCourseCategory(course);
                    return courseCategoryRepository.save(courseCategory);
                }
        ).orElseThrow(()->new ResourceNotFoundException("Not found"));
    }

    public void deleteCourseCategoryById(Long id){
        courseCategoryRepository.deleteById(id);
    }

    public CourseCategory deactivateCourseCategoryById(Long id) throws CourseCategoryNotFoundException {
       CourseCategory courseCategory = validateIfCourseCategoryExistsById(id);
       courseCategory.setCourseCategoryActive(false);
       courseCategory.setCourseCategoryUpdatedDate(new Date());

       courseCategoryRepository.save(courseCategory);
       return courseCategory;
    }

    private CourseCategory validateIfCourseCategoryExistsById(Long id) throws CourseCategoryNotFoundException {
        CourseCategory courseCategory = getCourseCategoryById(id);
        if( courseCategory == null ){
            throw new CourseCategoryNotFoundException("No course with id found");
        }
        return courseCategory;
    }
}
