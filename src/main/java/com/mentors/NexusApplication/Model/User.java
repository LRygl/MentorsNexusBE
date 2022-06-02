package com.mentors.NexusApplication.Model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import javax.persistence.*;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name="APPLICATION_USERS")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "userGenerator")
    @SequenceGenerator(name = "userGenerator", sequenceName = "application_user_sequence", allocationSize = 10)
    @Column(nullable = false,updatable = false)
    //@JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private Long id;
    private String userFirstName;
    private String userLastName;
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String userPassword;
    private String userEmail;
    private String userCompany;
    private String userProfileImageUrl;
    private String userRole;
    private String[] userAuthorities;

    private Date userLastLoginDate;
    private Date userLastLoginDateDisplay;
    private Date userJoinDate;
    private Date userLastUpdatedDate;
    private Boolean isActive;
    private Boolean isNotLocked;
    @ManyToMany(fetch = FetchType.LAZY,
            cascade = {
                    CascadeType.PERSIST,
                    CascadeType.MERGE
            })
    @JoinTable(name = "USER_COURSE",
            joinColumns = { @JoinColumn(name = "tutorial_id") },
            inverseJoinColumns = { @JoinColumn(name = "tag_id") })
    private Set<Course> enrolledCourses = new HashSet<>();

    @JsonIgnore
    @OneToMany(mappedBy = "courseCategory")
    private Set<Course> ownedCourses = new HashSet<>();

    public User() {
    }

    public User(Long id, String userFirstName, String userLastName, String userPassword, String userEmail, String userCompany, String userProfileImageUrl, String userRole, String[] userAuthorities, Date userLastLoginDate, Date userLastLoginDateDisplay, Date userJoinDate, Date userLastUpdatedDate, Boolean isActive, Boolean isNotLocked, Set<Course> enrolledCourses, Set<Course> ownedCourses) {
        this.id = id;
        this.userFirstName = userFirstName;
        this.userLastName = userLastName;
        this.userPassword = userPassword;
        this.userEmail = userEmail;
        this.userCompany = userCompany;
        this.userProfileImageUrl = userProfileImageUrl;
        this.userRole = userRole;
        this.userAuthorities = userAuthorities;
        this.userLastLoginDate = userLastLoginDate;
        this.userLastLoginDateDisplay = userLastLoginDateDisplay;
        this.userJoinDate = userJoinDate;
        this.userLastUpdatedDate = userLastUpdatedDate;
        this.isActive = isActive;
        this.isNotLocked = isNotLocked;
        this.enrolledCourses = enrolledCourses;
        this.ownedCourses = ownedCourses;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUserFirstName() {
        return userFirstName;
    }

    public void setUserFirstName(String userFirstName) {
        this.userFirstName = userFirstName;
    }

    public String getUserLastName() {
        return userLastName;
    }

    public void setUserLastName(String userLastName) {
        this.userLastName = userLastName;
    }

    public String getUserPassword() {
        return userPassword;
    }

    public void setUserPassword(String userPassword) {
        this.userPassword = userPassword;
    }

    public String getUserEmail() {
        return userEmail;
    }

    public void setUserEmail(String userEmail) {
        this.userEmail = userEmail;
    }

    public String getUserCompany() {
        return userCompany;
    }

    public void setUserCompany(String userCompany) {
        this.userCompany = userCompany;
    }

    public String getUserProfileImageUrl() {
        return userProfileImageUrl;
    }

    public void setUserProfileImageUrl(String userProfileImageUrl) {
        this.userProfileImageUrl = userProfileImageUrl;
    }

    public String getUserRole() {
        return userRole;
    }

    public void setUserRole(String userRole) {
        this.userRole = userRole;
    }

    public String[] getUserAuthorities() {
        return userAuthorities;
    }

    public void setUserAuthorities(String[] userAuthorities) {
        this.userAuthorities = userAuthorities;
    }

    public Date getUserLastLoginDate() {
        return userLastLoginDate;
    }

    public void setUserLastLoginDate(Date userLastLoginDate) {
        this.userLastLoginDate = userLastLoginDate;
    }

    public Date getUserLastLoginDateDisplay() {
        return userLastLoginDateDisplay;
    }

    public void setUserLastLoginDateDisplay(Date userLastLoginDateDisplay) {
        this.userLastLoginDateDisplay = userLastLoginDateDisplay;
    }

    public Date getUserJoinDate() {
        return userJoinDate;
    }

    public void setUserJoinDate(Date userJoinDate) {
        this.userJoinDate = userJoinDate;
    }

    public Date getUserLastUpdatedDate() {
        return userLastUpdatedDate;
    }

    public void setUserLastUpdatedDate(Date userLastUpdatedDate) {
        this.userLastUpdatedDate = userLastUpdatedDate;
    }

    public Boolean getActive() {
        return isActive;
    }

    public void setActive(Boolean active) {
        isActive = active;
    }

    public Boolean getNotLocked() {
        return isNotLocked;
    }

    public void setNotLocked(Boolean notLocked) {
        isNotLocked = notLocked;
    }

    public Set<Course> getEnrolledCourses() {
        return enrolledCourses;
    }

    public void setEnrolledCourses(Set<Course> enrolledCourses) {
        this.enrolledCourses = enrolledCourses;
    }

    public Set<Course> getOwnedCourses() {
        return ownedCourses;
    }

    public void setOwnedCourses(Set<Course> ownedCourses) {
        this.ownedCourses = ownedCourses;
    }

    public void addUserToCourse(Course course){
        this.enrolledCourses.add(course);
        course.getEnrolledUsers().add(this);
    }

    public void removeUserFromCourse(Course course){
        this.enrolledCourses.remove(course);
        course.getEnrolledUsers().remove(this);
    }

}
