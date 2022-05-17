package com.mentors.NexusApplication.Model;

import com.fasterxml.jackson.annotation.JsonIgnore;

import javax.persistence.*;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name="COURSE_CATEGORY")
public class CourseCategory {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "categoryGenerator")
    @SequenceGenerator(name = "categoryGenerator", sequenceName = "course_category_sequence", allocationSize = 10)
    @Column(nullable = false, updatable = false)
    private Long id;
    private String courseCategoryName;
    private String courseCategoryDescription;
    @Column(length = 4)
    private String courseCategoryCode;
    private Date courseCategoryCreatedDate;
    private Date courseCategoryUpdatedDate;
    private Boolean isCourseCategoryActive;
    @OneToMany(
            mappedBy = "courseCategory",
            fetch = FetchType.LAZY,
            cascade = CascadeType.ALL
    )
    @JsonIgnore
    private Set<Course> courses = new HashSet<>();

    public CourseCategory() {
    }

    public CourseCategory(Long id, String courseCategoryName, String courseCategoryDescription, String courseCategoryCode, Date courseCategoryCreatedDate, Date courseCategoryUpdatedDate, Boolean isCourseCategoryActive, Set<Course> courses) {
        this.id = id;
        this.courseCategoryName = courseCategoryName;
        this.courseCategoryDescription = courseCategoryDescription;
        this.courseCategoryCode = courseCategoryCode;
        this.courseCategoryCreatedDate = courseCategoryCreatedDate;
        this.courseCategoryUpdatedDate = courseCategoryUpdatedDate;
        this.isCourseCategoryActive = isCourseCategoryActive;
        this.courses = courses;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getCourseCategoryName() {
        return courseCategoryName;
    }

    public void setCourseCategoryName(String courseCategoryName) {
        this.courseCategoryName = courseCategoryName;
    }

    public String getCourseCategoryDescription() {
        return courseCategoryDescription;
    }

    public void setCourseCategoryDescription(String courseCategoryDescription) {
        this.courseCategoryDescription = courseCategoryDescription;
    }

    public String getCourseCategoryCode() {
        return courseCategoryCode;
    }

    public void setCourseCategoryCode(String courseCategoryCode) {
        this.courseCategoryCode = courseCategoryCode;
    }

    public Date getCourseCategoryCreatedDate() {
        return courseCategoryCreatedDate;
    }

    public void setCourseCategoryCreatedDate(Date courseCategoryCreatedDate) {
        this.courseCategoryCreatedDate = courseCategoryCreatedDate;
    }

    public Date getCourseCategoryUpdatedDate() {
        return courseCategoryUpdatedDate;
    }

    public void setCourseCategoryUpdatedDate(Date courseCategoryUpdatedDate) {
        this.courseCategoryUpdatedDate = courseCategoryUpdatedDate;
    }

    public Boolean getCourseCategoryActive() {
        return isCourseCategoryActive;
    }

    public void setCourseCategoryActive(Boolean courseCategoryActive) {
        isCourseCategoryActive = courseCategoryActive;
    }

    public Set<Course> getCourses() {
        return courses;
    }

    public void setCourses(Set<Course> courses) {
        this.courses = courses;
    }

    public void addCourseCategory(Course course){
        courses.add(course);
        course.setCourseCategory(this);
    }
}