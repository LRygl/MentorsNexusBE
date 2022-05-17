package com.mentors.NexusApplication.Service.Impl;

import com.mentors.NexusApplication.Enum.Role;
import com.mentors.NexusApplication.Exceptions.*;
import com.mentors.NexusApplication.Model.Course;
import com.mentors.NexusApplication.Model.User;
import com.mentors.NexusApplication.Model.UserPrincipal;
import com.mentors.NexusApplication.Repository.CourseRepository;
import com.mentors.NexusApplication.Repository.UserRepository;
import com.mentors.NexusApplication.Service.EmailService;
import com.mentors.NexusApplication.Service.LoginAttemptService;
import com.mentors.NexusApplication.Service.UserService;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;

import javax.mail.MessagingException;
import javax.transaction.Transactional;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.List;

import static com.mentors.NexusApplication.Constants.FileConstant.*;
import static com.mentors.NexusApplication.Constants.UserImplementationConstant.*;
import static com.mentors.NexusApplication.Enum.Role.ROLE_SUPER_ADMIN;
import static com.mentors.NexusApplication.Enum.Role.ROLE_USER;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;

@Service
@Transactional
@Qualifier("userDetailService")
public class UserServiceImpl implements UserService, UserDetailsService {

    private static final Logger logger = LoggerFactory.getLogger(UserServiceImpl.class);

    private final UserRepository userRepository;
    private final CourseRepository courseRepository;
    private final LoginAttemptService loginAttemptService;
    private final BCryptPasswordEncoder passwordEncoder;
    private final EmailService emailService;

    @Autowired
    public UserServiceImpl(UserRepository userRepository,CourseRepository courseRepository,BCryptPasswordEncoder passwordEncoder,LoginAttemptService loginAttemptService,EmailService emailService) {
        this.userRepository = userRepository;
        this.courseRepository = courseRepository;
        this.loginAttemptService = loginAttemptService;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
    }

    @Override
    public List<User> getUsers() {
        return userRepository.findAll();
    }

    @Override
    public Page<User> getUserPaginationAndSorting(Integer pageNumber, Integer pageSize, String sortDirection, String sortBy){
        Sort sort = Sort.by(getSortDirection(sortDirection), sortBy);
        Pageable pageable = PageRequest.of(pageNumber,pageSize,sort);
        return userRepository.findAll(pageable);
    }

    private Sort.Direction getSortDirection(String sortDirection){
        if(sortDirection.equals("desc")){
            return Sort.Direction.DESC;
        }
        return Sort.Direction.ASC;
    }

    public User findUserById(Long id){
        return userRepository.findUserById(id);
    }

    @Override
    public User findUserByUsername(String username) {
        return userRepository.findUserByUsername(username);
    }

    @Override
    public User findUserByEmail(String email){
        return userRepository.findUserByUserEmail(email);
    }

    @Override
    public Boolean deleteUserById(Long id) {
        userRepository.deleteById(id);
        return Boolean.TRUE;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findUserByUsername(username);
        if (user == null){
            logger.error("User not found by username: " + username);
            throw new UsernameNotFoundException("User not found");
        } else {
            validateLoginAttempt(user);
            user.setUserLastLoginDateDisplay(user.getUserLastLoginDate());
            user.setUserLastLoginDate(new Date());
            userRepository.save(user);

            UserPrincipal userPrincipal = new UserPrincipal(user);
            logger.info("Returning found user by username " + username);
            return userPrincipal;
        }
    }

    private void validateLoginAttempt(User user) {
        if (user.getNotLocked()){
            if (loginAttemptService.hasExceededMaxAttempts(user.getUsername())){
                user.setNotLocked(false);
            } else {
                user.setNotLocked(true);
            }
        } else {
            loginAttemptService.evictUserFromLoginAttemptCache(user.getUsername());
        }
    }

    @Override
    public User register(String firstName, String lastName, String username, String email) throws UserNotFoundException, EmailExistsException, UsernameExistsException, MessagingException {
        validateNewUsernameAndEmail(StringUtils.EMPTY, username,email);
        User user = new User();
        //user.setUserId(generateUserId());

        String password = generatePassword();
        user.setUserFirstName(firstName);
        user.setUserLastName(lastName);
        user.setUsername(username);
        user.setUserEmail(email);
        user.setUserJoinDate(new Date());
        user.setUserPassword(encodePassword(password));
        user.setActive(true);
        user.setNotLocked(true);
        user.setUserRole(ROLE_USER.name());
        user.setUserAuthorities(ROLE_USER.getAuthorities());
        user.setUserProfileImageUrl(getTemporaryProfileImageUrl(username));
        userRepository.save(user);
        logger.info("New user created " + username + " " + user.getId());
        logger.info("User Password is " + password);
        /*emailService.sendNewPasswordEmail(firstName,password,email);*/
        logger.info(NEW_USER_WAS_SUCCESSFULY_CREATED + username + (user.getId()) + ") with email " + email);
        return user;
    }

    @Override
    public User addNewUser(String firstName, String lastName, String username, String email, String role, boolean isNonLocked, boolean isActive, MultipartFile profileImage) throws UserNotFoundException, EmailExistsException, UsernameExistsException, IOException {
        validateNewUsernameAndEmail(StringUtils.EMPTY, username, email);
        User user = new User();
        String password = generateUserPassword();
        String encodedPassword = encodePassword(password);
        user.setUserFirstName(firstName);
        user.setUserLastName(lastName);
        user.setUserJoinDate(new Date());
        user.setUsername(username);
        user.setUserEmail(email);
        user.setUserPassword(password);
        user.setActive(isActive);
        user.setNotLocked(isNonLocked);
        user.setUserRole(getRoleEnumName(role).name());
        user.setUserAuthorities(getRoleEnumName(role).getAuthorities());
        user.setUserProfileImageUrl(getTemporaryProfileImageUrl(username));
        userRepository.save(user);
        saveProfileImage(user, profileImage);
        return user;
    }

    @Override
    public void addAdminUser(String firstName, String lastName, String username, String email) {
        User user = new User();
        String encodedPassword = encodePassword("admin");
        user.setUserFirstName(firstName);
        user.setUserLastName(lastName);
        user.setUserJoinDate(new Date());
        user.setUsername(username);
        user.setUserEmail(email);
        user.setUserPassword(encodedPassword);
        user.setActive(true);
        user.setNotLocked(true);
        user.setUserRole(getRoleEnumName("ROLE_SUPER_ADMIN").name());
        user.setUserAuthorities(getRoleEnumName("ROLE_SUPER_ADMIN").getAuthorities());
        //user.setUserProfileImageUrl(getTemporaryProfileImageUrl(username));
        userRepository.save(user);
    }

    @Override
    public User updateUser(String currentUsername, String newFirstName, String newLastName, String newUsername, String newEmail, String role, boolean isNonLocked, boolean isActive, MultipartFile profileImage) throws UserNotFoundException, EmailExistsException, UsernameExistsException, IOException {
        User currentUser = validateNewUsernameAndEmail(currentUsername, newUsername, newEmail);
        currentUser.setUserFirstName(newFirstName);
        currentUser.setUserLastName(newLastName);
        currentUser.setUsername(newUsername);
        currentUser.setUserEmail(newEmail);
        currentUser.setActive(isActive);
        currentUser.setNotLocked(isNonLocked);
        currentUser.setUserRole(getRoleEnumName(role).name());
        currentUser.setUserAuthorities(getRoleEnumName(role).getAuthorities());
        userRepository.save(currentUser);
        saveProfileImage(currentUser, profileImage);
        return currentUser;
    }
    //TODO Check if course is published
    public User enrollUserToCourse(Long courseId, Long userId) throws ResourceNotFoundException {
        Course course = courseRepository.findCourseById(courseId);
        //User user = userRepository.findUserById(userId);
        User user = userRepository.findById(userId).orElseThrow(() -> new ResourceNotFoundException("Not found"));
        user.addUserToCourse(course);

        return userRepository.save(user);
    }

    public User removeUserFromCourse(Long courseId, Long userId) {
        Course course = courseRepository.findCourseById(courseId);
        User user = userRepository.findUserById(userId);
        user.removeUserFromCourse(course);

        return userRepository.save(user);
    }


    private @Nullable User validateNewUsernameAndEmail(String currentUserName, String newUserName, String userEmail) throws EmailExistsException, UsernameExistsException, UserNotFoundException {
        User userByNewUsername = findUserByUsername(newUserName);
        User userByNewEmail = findUserByEmail(userEmail);

        if(StringUtils.isNotBlank(currentUserName)) {
            //User with username does not exist
            User currentUser = findUserByUsername(currentUserName);
            if (currentUser == null){
                throw new UserNotFoundException(NO_USER_FOUND_BY_USERNAME + currentUserName);
            }
            if (userByNewUsername != null && !currentUser.getId().equals(userByNewUsername.getId())) {
                throw new UsernameExistsException(USERNAME_ALREADY_EXIST);
            }
            if (userByNewEmail != null && !currentUser.getId().equals(userByNewEmail.getId())) {
                throw new EmailExistsException(EMAIL_ALREADY_EXIST);
            }
            return currentUser;
        } else {
            if (userByNewUsername != null){
                throw new UsernameExistsException(USERNAME_ALREADY_EXIST);
            }
            if (userByNewEmail != null) {
                throw new EmailExistsException(EMAIL_ALREADY_EXIST);
            }
            return null;
        }
    }
    private String generateUserPassword(){
        return RandomStringUtils.randomAlphanumeric(10);
    }

    @Override
    public void resetUserPassword(String email, String username) throws MessagingException, EmailNotFoundException, PasswordResetException {
        User user = userRepository.findUserByUserEmail(email);
        if (user == null){
            throw new EmailNotFoundException(NO_USER_FOUND_BY_EMAIL + email);
        }
        if (user.getUsername() == username){
            String password = generatePassword();
            user.setUserPassword(encodePassword(password));
            userRepository.save(user);
            emailService.sendNewPasswordEmail(user.getUserFirstName(),password,user.getUserEmail());
        }
        throw new PasswordResetException("MESSAGE PASSWORD RESET NOT POSSIBLE");

    }

    public void changeUserPassword(String currentPassword,String newPassword, Long userId) throws PasswordResetException {
        User user = userRepository.findUserById(userId);

       if(passwordEncoder.matches(currentPassword,user.getUserPassword())){
           user.setUserPassword(passwordEncoder.encode(newPassword));
           userRepository.save(user);
       } else {
           throw new PasswordResetException("Passwords do not match");
       }

    }

    @Override
    public User updateProfileImage(String username, MultipartFile profileImage) throws UserNotFoundException, EmailExistsException, UsernameExistsException, IOException {

        User user = validateNewUsernameAndEmail(username,null,null);
        saveProfileImage(user,profileImage);
        return user;
    }

    private void saveProfileImage(User user, MultipartFile profileImage) throws IOException {
        if (profileImage != null){
            Path userFolder = Paths.get(USER_FOLDER + user.getUsername()).toAbsolutePath().normalize();
            if(!Files.exists(userFolder)){
                Files.createDirectories(userFolder);
                logger.info("Directory created" + userFolder);
            }
            Files.deleteIfExists(Paths.get(userFolder + user.getUsername() + DOT + JPG_EXTENSION));
            Files.copy(profileImage.getInputStream(),userFolder.resolve(user.getUsername() + DOT + JPG_EXTENSION), REPLACE_EXISTING);
            user.setUserProfileImageUrl(setProfileImageUrl(user.getUsername()));
            userRepository.save(user);
            logger.info(FILE_SAVED_IN_FILE_SYSTEM + profileImage.getOriginalFilename());
        }
    }

    private String setProfileImageUrl(String username) {
        return ServletUriComponentsBuilder.fromCurrentContextPath().path(USER_IMAGE_PATH + username + FORWARD_SLASH + username + DOT + JPG_EXTENSION).toUriString();
    }

    private Role getRoleEnumName(String role) {
        return Role.valueOf(role.toUpperCase());
    }

    private String generatePassword(){
        return RandomStringUtils.randomAlphanumeric(10);
    }

    private String encodePassword(String password){
        return passwordEncoder.encode(password);
    }

    private String getTemporaryProfileImageUrl(String username){
        return ServletUriComponentsBuilder.fromCurrentContextPath().path(DEFAULT_USER_IMAGE_PATH + username).toUriString();
    }



}
