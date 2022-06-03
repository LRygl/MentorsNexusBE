package com.mentors.NexusApplication.Service;

import com.mentors.NexusApplication.Exceptions.*;
import com.mentors.NexusApplication.Model.User;
import org.springframework.data.domain.Page;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import java.io.IOException;
import java.util.List;
import java.util.Optional;

public interface UserService {

    List<User> getUsers();

    Page<User> getUserPaginationAndSorting(Integer page, Integer pageSize,String sortDirection, String sortBy);

    User register(String firstName, String lastName, String email) throws UserNotFoundException, EmailExistsException, UsernameExistsException, MessagingException, EmailNotFoundException;
    User addNewUser(String firstName, String lastName, String email, String role, boolean isNonLocked, boolean isActive, MultipartFile profileImage) throws UserNotFoundException, EmailExistsException, UsernameExistsException, IOException, UserNotFoundException, EmailNotFoundException;
    User updateUser(String currentUsername, String newFirstName, String newLastName, String newEmail, String role, boolean isNonLocked, boolean isActive, MultipartFile profileImage) throws UserNotFoundException, EmailExistsException, UsernameExistsException, IOException;
    User findUserByEmail(String email);
    User enrollUserToCourse(Long courseId, Long userId) throws ResourceNotFoundException;
    User removeUserFromCourse(Long courseId, Long userId);
    User updateProfileImage(String username, MultipartFile profileImage) throws UserNotFoundException, EmailExistsException, UsernameExistsException, IOException;
    void changeUserPassword(String currentPassword,String newPassword, Long userId) throws PasswordResetException;
    void resetUserPassword(String email) throws MessagingException, EmailNotFoundException, PasswordResetException;
    void addAdminUser(String firstName, String lastName, String email);

    Boolean deleteUserById(Long id);

}
