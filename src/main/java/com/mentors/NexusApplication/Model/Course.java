package com.mentors.NexusApplication.Model;

import com.fasterxml.jackson.annotation.JsonIgnore;

import javax.persistence.*;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name="COURSE")
public class Course {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "courseGenerator")
    @SequenceGenerator(name = "courseGenerator", sequenceName = "course_sequence", allocationSize = 10)
    @Column(nullable = false, updatable = false)
    //@JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private Long id;
    private UUID courseUUID;
    private String courseName;
    private String courseDescription;
    private Long courseOwnerId;
    private Date courseCreated;
    private Date coursePublishDate;
    private Date courseUpdated;
    private Boolean isPublished;
    private Boolean isPrivate;
    @ManyToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "course_category_id",referencedColumnName = "id")
    private CourseCategory courseCategory;

    @ManyToMany(fetch = FetchType.LAZY,
                cascade = {
                    CascadeType.PERSIST,
                    CascadeType.MERGE
            },
            mappedBy = "enrolledCourses")
    @JsonIgnore
    private Set<User> enrolledUsers = new HashSet<>();

    public Course() {
    }

    public Course(Long id, UUID courseUUID, String courseName, String courseDescription, Long courseOwnerId, Date courseCreated, Date coursePublishDate, Date courseUpdated, Boolean isPublished, Boolean isPrivate, CourseCategory courseCategory, Set<User> enrolledUsers) {
        this.id = id;
        this.courseUUID = courseUUID;
        this.courseName = courseName;
        this.courseDescription = courseDescription;
        this.courseOwnerId = courseOwnerId;
        this.courseCreated = courseCreated;
        this.coursePublishDate = coursePublishDate;
        this.courseUpdated = courseUpdated;
        this.isPublished = isPublished;
        this.isPrivate = isPrivate;
        this.courseCategory = courseCategory;
        this.enrolledUsers = enrolledUsers;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public UUID getCourseUUID() {
        return courseUUID;
    }

    public void setCourseUUID(UUID courseId) {
        this.courseUUID = courseId;
    }

    public String getCourseName() {
        return courseName;
    }

    public void setCourseName(String courseName) {
        this.courseName = courseName;
    }

    public String getCourseDescription() {
        return courseDescription;
    }

    public void setCourseDescription(String courseDescription) {
        this.courseDescription = courseDescription;
    }

    public Long getCourseOwnerId() {
        return courseOwnerId;
    }

    public void setCourseOwnerId(Long courseOwnerId) {
        this.courseOwnerId = courseOwnerId;
    }

    public Date getCourseCreated() {
        return courseCreated;
    }

    public void setCourseCreated(Date courseCreated) {
        this.courseCreated = courseCreated;
    }

    public Date getCoursePublishDate() {
        return coursePublishDate;
    }

    public void setCoursePublishDate(Date coursePublishDate) {
        this.coursePublishDate = coursePublishDate;
    }

    public Date getCourseUpdated() {
        return courseUpdated;
    }

    public void setCourseUpdated(Date courseUpdated) {
        this.courseUpdated = courseUpdated;
    }

    public Boolean getPublished() {
        return isPublished;
    }

    public void setPublished(Boolean published) {
        isPublished = published;
    }

    public Boolean getPrivate() {
        return isPrivate;
    }

    public void setPrivate(Boolean aPrivate) {
        isPrivate = aPrivate;
    }

    public CourseCategory getCourseCategory() {
        return courseCategory;
    }

    public void setCourseCategory(CourseCategory courseCategory) {
        this.courseCategory = courseCategory;
    }

    public Set<User> getEnrolledUsers() {
        return enrolledUsers;
    }

    public void setEnrolledUsers(Set<User> enrolledUsers) {
        this.enrolledUsers = enrolledUsers;
    }

    public void enrollToCourse(User user) {
        enrolledUsers.add(user);
    }


}


