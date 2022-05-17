package com.mentors.NexusApplication.Repository;

import com.mentors.NexusApplication.Model.CourseCategory;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CourseCategoryRepository extends JpaRepository<CourseCategory, Long> {

    CourseCategory findCourseCategoryById(Long id);
    //@EntityGraph(value="CourseCategory.courses", type = EntityGraph.EntityGraphType.FETCH)
    //List<CourseCategory> findBycoursesId(Long id);
}
