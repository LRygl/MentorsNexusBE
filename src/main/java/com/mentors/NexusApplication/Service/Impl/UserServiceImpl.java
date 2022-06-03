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
    public User findUserByEmail(String email){
        return userRepository.findUserByUserEmail(email);
    }

    public Boolean userExistsByEmail(String userEmail) throws EmailExistsException {
        User result = userRepository.findUserByUserEmail((userEmail));
        if(userRepository.findUserByUserEmail(userEmail)==null){
            return false;
        } else
            throw new EmailExistsException("EMAIL EXISTS");
    }

    @Override
    public Boolean deleteUserById(Long id) {
        userRepository.deleteById(id);
        return Boolean.TRUE;
    }

    @Override
    public UserDetails loadUserByUsername(String userEmail) throws UsernameNotFoundException {
        User user = userRepository.findUserByUserEmail(userEmail);
        if (user == null){
            logger.error("User not found by username: " + userEmail);
            throw new UsernameNotFoundException("User not found");
        } else {
            validateLoginAttempt(user);
            user.setUserLastLoginDateDisplay(user.getUserLastLoginDate());
            user.setUserLastLoginDate(new Date());
            userRepository.save(user);

            UserPrincipal userPrincipal = new UserPrincipal(user);
            logger.info("Returning found user by username " + userEmail);
            return userPrincipal;
        }
    }

    private void validateLoginAttempt(User user) {
        if (user.getNotLocked()){
            if (loginAttemptService.hasExceededMaxAttempts(user.getUserEmail())){
                user.setNotLocked(false);
            } else {
                user.setNotLocked(true);
            }
        } else {
            loginAttemptService.evictUserFromLoginAttemptCache(user.getUserEmail());
        }
    }

    @Override
    public User register(String firstName, String lastName, String userEmail) throws UserNotFoundException, EmailExistsException, UsernameExistsException, MessagingException, EmailNotFoundException {
        userExistsByEmail(userEmail);
        User user = new User();
        //user.setUserId(generateUserId());

        String password = generatePassword();
        user.setUserFirstName(firstName);
        user.setUserLastName(lastName);
        user.setUserEmail(userEmail);
        user.setUserJoinDate(new Date());
        user.setUserPassword(encodePassword(password));
        user.setActive(true);
        user.setNotLocked(true);
        user.setUserRole(ROLE_USER.name());
        user.setUserAuthorities(ROLE_USER.getAuthorities());
        user.setUserProfileImageUrl(getTemporaryProfileImageUrl(userEmail));
        userRepository.save(user);
        logger.info("New user created " + userEmail + " " + user.getId());
        logger.info("User Password is " + password);
        /*emailService.sendNewPasswordEmail(firstName,password,email);*/
        logger.info(NEW_USER_WAS_SUCCESSFULY_CREATED + userEmail + (user.getId()) + ") with email " + userEmail);
        return user;
    }

    @Override
    public User addNewUser(String firstName, String lastName, String userEmail, String role, boolean isNonLocked, boolean isActive, MultipartFile profileImage) throws UserNotFoundException, EmailExistsException, UsernameExistsException, IOException, EmailNotFoundException {
        validateNewEmail(userEmail);
        User user = new User();
        String password = generateUserPassword();
        String encodedPassword = encodePassword(password);
        user.setUserFirstName(firstName);
        user.setUserLastName(lastName);
        user.setUserJoinDate(new Date());
        user.setUserEmail(userEmail);
        user.setUserPassword(password);
        user.setActive(isActive);
        user.setNotLocked(isNonLocked);
        user.setUserRole(getRoleEnumName(role).name());
        user.setUserAuthorities(getRoleEnumName(role).getAuthorities());
        user.setUserProfileImageUrl(getTemporaryProfileImageUrl(userEmail));
        userRepository.save(user);
        saveProfileImage(user, profileImage);
        return user;
    }

    public void addAdminUser(String firstName, String lastName, String email) {
        User user = new User();
        String encodedPassword = encodePassword("admin");
        user.setUserFirstName(firstName);
        user.setUserLastName(lastName);
        user.setUserJoinDate(new Date());
        user.setUserEmail(email);
        user.setUserPassword(encodedPassword);
        user.setActive(true);
        user.setNotLocked(true);
        user.setUserRole(getRoleEnumName("ROLE_SUPER_ADMIN").name());
        user.setUserAuthorities(getRoleEnumName("ROLE_SUPER_ADMIN").getAuthorities());
        //user.setUserProfileImageUrl(getTemporaryProfileImageUrl(username));
        logger.info(encodedPassword);
        userRepository.save(user);
    }

    @Override
    public User updateUser(String currentUsername, String newFirstName, String newLastName, String newEmail, String role, boolean isNonLocked, boolean isActive, MultipartFile profileImage) throws UserNotFoundException, EmailExistsException, UsernameExistsException, IOException {
        User currentUser = validateNewEmail(newEmail);
        currentUser.setUserFirstName(newFirstName);
        currentUser.setUserLastName(newLastName);
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


    private @Nullable User validateNewEmail(String userEmail) throws EmailExistsException, UserNotFoundException {
        User user = findUserByEmail(userEmail);
        if(StringUtils.isNotBlank(userEmail)) {
            //User with username does not exist
            if (user == null){
                throw new UserNotFoundException(NO_USER_FOUND_BY_USERNAME + userEmail);
            }
            if (user != null && !user.getUserEmail().equals(userEmail)) {
                throw new EmailExistsException(USERNAME_ALREADY_EXIST);
            }
            return user;
        } else {
            return null;
        }
    }
    private String generateUserPassword(){
        return RandomStringUtils.randomAlphanumeric(10);
    }
    public void resetUserPassword(String email) throws MessagingException, EmailNotFoundException, PasswordResetException {
        User user = userRepository.findUserByUserEmail(email);
        if (user != null){
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
    public User updateProfileImage(String userEmail, MultipartFile profileImage) throws UserNotFoundException, EmailExistsException, UsernameExistsException, IOException {

        User user = validateNewEmail(userEmail);
        saveProfileImage(user,profileImage);
        return user;
    }

    private void saveProfileImage(User user, MultipartFile profileImage) throws IOException {
        if (profileImage != null){
            Path userFolder = Paths.get(USER_FOLDER + user.getId()).toAbsolutePath().normalize();
            if(!Files.exists(userFolder)){
                Files.createDirectories(userFolder);
                logger.info("Directory created" + userFolder);
            }
            Files.deleteIfExists(Paths.get(userFolder + Long.toString(user.getId()) + DOT + JPG_EXTENSION));
            Files.copy(profileImage.getInputStream(),userFolder.resolve(Long.toString(user.getId()) + DOT + JPG_EXTENSION), REPLACE_EXISTING);
            user.setUserProfileImageUrl(setProfileImageUrl(Long.toString(user.getId())));
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
