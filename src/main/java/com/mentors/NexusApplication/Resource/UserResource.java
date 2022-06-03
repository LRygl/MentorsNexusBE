package com.mentors.NexusApplication.Resource;

import com.mentors.NexusApplication.Exceptions.*;
import com.mentors.NexusApplication.Model.HttpResponse;
import com.mentors.NexusApplication.Model.User;
import com.mentors.NexusApplication.Model.UserPrincipal;
import com.mentors.NexusApplication.Service.Impl.UserServiceImpl;
import com.mentors.NexusApplication.Service.UserService;
import com.mentors.NexusApplication.Utils.JwtTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static com.mentors.NexusApplication.Constants.SecurityConstant.JWT_TOKEN_HEADER;

@RestController
@RequestMapping(path = {"/","/user"})
public class UserResource {
    private static final Logger LOGGER = LoggerFactory.getLogger(UserServiceImpl.class);

    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;

    public UserResource(UserService userService, AuthenticationManager authenticationManager,JwtTokenProvider jwtTokenProvider) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;

    }

    @GetMapping("/list")
    public ResponseEntity<List<User>> getAllUsers(){
        List<User> users = userService.getUsers();
        LOGGER.debug("Returning all users" + users);
        return new ResponseEntity<>(users, HttpStatus.OK);
    }

    @GetMapping("/pagingUsers")
    public Page<User> userPaginationAndSorting(@RequestParam(value = "page",defaultValue = "0", required = false) Integer page,
                                               @RequestParam(value = "pageSize", defaultValue = "10", required = false) Integer pageSize,
                                               @RequestParam(value = "order",defaultValue = "ASC", required = false) String sortDirection,
                                               @RequestParam(value = "sort", defaultValue = "id", required = false) String sortBy){
        return userService.getUserPaginationAndSorting(page,pageSize,sortDirection,sortBy);
    }

    @PostMapping("/add")
    public ResponseEntity<User> addNewUser(@RequestParam("firstName") String firstName,
                                           @RequestParam("lastName") String lastName,
                                           @RequestParam("username") String username,
                                           @RequestParam("email") String email,
                                           @RequestParam("role") String role,
                                           @RequestParam("isActive") String isActive,
                                           @RequestParam("isNonLocked") String isNonLocked,
                                           @RequestParam(value = "profileImage", required = false) MultipartFile profileImage) throws UserNotFoundException, EmailExistsException, UsernameExistsException, IOException, EmailNotFoundException {
        User newUser = userService.addNewUser(firstName, lastName, email, role, Boolean.parseBoolean(isActive) ,Boolean.parseBoolean(isNonLocked), profileImage);
        LOGGER.debug("Returning all users");
        return new ResponseEntity<>(newUser, HttpStatus.OK);
    }

    @PostMapping("/{userId}/course/{courseId}")
    public ResponseEntity<User> enrollUserToCourse(
            @PathVariable(value="courseId") Long courseId,
            @PathVariable(value="userId") Long userId) throws ResourceNotFoundException {
        User course = userService.enrollUserToCourse(courseId,userId);

        return new ResponseEntity<>(course,HttpStatus.OK);
    }

    @PutMapping("/update")
    public ResponseEntity<User> update(@RequestParam("currentUsername") String currentUsername,
                                       @RequestParam("firstName") String firstName,
                                       @RequestParam("lastName") String lastName,
                                       @RequestParam("username") String username,
                                       @RequestParam("email") String email,
                                       @RequestParam("role") String role,
                                       @RequestParam("isActive") String isActive,
                                       @RequestParam("isNonLocked") String isNonLocked,
                                       @RequestParam(value = "profileImage", required = false) MultipartFile profileImage) throws UserNotFoundException, EmailExistsException, UsernameExistsException, IOException {
        User updateUser = userService.updateUser(firstName, lastName, username, email, role, Boolean.parseBoolean(isActive) ,Boolean.parseBoolean(isNonLocked), profileImage);
        return new ResponseEntity<>(updateUser, HttpStatus.OK);
    }

    @PutMapping("/{id}/updatePassword")
    public ResponseEntity<String> updateUserPassword(
            @RequestParam("currentPassword") String currentPassword,
            @RequestParam("newPassword") String newPassword,
            @PathVariable("id") Long userId) throws PasswordResetException {
        userService.changeUserPassword(currentPassword, newPassword, userId);
        return new ResponseEntity<>("OK", HttpStatus.OK);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<HttpResponse> deleteUserById(@PathVariable("id") Long id) throws UserNotFoundException {
        return ResponseEntity.ok(
                HttpResponse.builder()
                        .httpStatus(HttpStatus.OK)
                        .httpStatusCode(HttpStatus.OK.value())
                        .httpTimestamp(new Date(System.currentTimeMillis()))
                        .httpResponseData(Map.of("Deleted",userService.deleteUserById(id)))
                        .httpStatusMessage("User deleted " + id)
                        .httpDeveloperMessage("Oops")
                        .httpStatusReason("test")
                        .build()
        );
    }

    @DeleteMapping("/{userId}/course/{courseId}")
    public ResponseEntity<User> removeUserFromCourse(
            @PathVariable(value="courseId") Long courseId,
            @PathVariable(value="userId") Long userId)
    {
        User course = userService.removeUserFromCourse(courseId,userId);
        return new ResponseEntity<>(course,HttpStatus.OK);
    }

    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody User user) throws UserNotFoundException, EmailExistsException, UsernameExistsException, MessagingException, EmailNotFoundException {
        User newUser = userService.register(user.getUserFirstName(), user.getUserLastName(), user.getUserEmail());
        LOGGER.debug("Registered a new user " + newUser);
        return new ResponseEntity<>(newUser, HttpStatus.OK);
    }

    @PostMapping("/login")
    public ResponseEntity<User> login(@RequestBody User user) {
        authenticate(user.getUserEmail(), user.getUserPassword());
        User loginUser = userService.findUserByEmail(user.getUserEmail());
        UserPrincipal userPrincipal = new UserPrincipal((loginUser));
        HttpHeaders jwtHeader = getJwtHeader(userPrincipal);
        LOGGER.info("Logged in a new user with principal " + userPrincipal + " and token  " + jwtHeader + " for user " + loginUser);
        return new ResponseEntity<>(loginUser, jwtHeader , HttpStatus.OK);
    }
    @PostMapping("/resetpassword")
    public ResponseEntity<User> resetUserPassword(@RequestBody User user) throws EmailNotFoundException, MessagingException, PasswordResetException {
        userService.resetUserPassword(user.getUserEmail());
        LOGGER.info("Reseting user password");
        return new ResponseEntity<>(null,null,HttpStatus.OK);
    }

    //PRIVATE METHODS
    private HttpHeaders getJwtHeader(UserPrincipal userPrincipal) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(JWT_TOKEN_HEADER, jwtTokenProvider.generateJwtToken(userPrincipal));
        LOGGER.info("HEaders for JWT" + headers);
        return headers;
    }

    private void authenticate(String userEmail, String userPassword) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userEmail,userPassword));
    }

}
