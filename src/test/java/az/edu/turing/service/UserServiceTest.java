package az.edu.turing.service;

import az.edu.turing.dao.entity.UserEntity;
import az.edu.turing.dao.repository.UserRepository;
import az.edu.turing.exceptions.BadRequestException;
import az.edu.turing.exceptions.NotFoundException;
import az.edu.turing.mapper.UserMapper;
import az.edu.turing.model.dto.request.UpdateUserRequest;
import az.edu.turing.model.dto.response.RetrieveUserResponse;
import az.edu.turing.auth.AuthorizationHelperService;
import az.edu.turing.clients.MsTransferClient;
import az.edu.turing.model.enums.Error;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import java.util.Optional;
import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private MsTransferClient msTransferClient;

    @Mock
    private UserMapper userMapper;

    @Mock
    private AuthorizationHelperService authorizationHelperService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserService userService;

    private final String validToken = "valid-token";
    private final String expiredToken = "expired-token";
    private final Long userId = 1L;
    private UserEntity userEntity;
    private RetrieveUserResponse userResponse;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        userEntity = new UserEntity();
        userEntity.setId(userId);
        userEntity.setName("John");
        userEntity.setSurname("Doe");
        userEntity.setEmail("john.doe@example.com");
        userEntity.setPassword("encoded-password");

        userResponse = RetrieveUserResponse.builder()
                .id(userId)
                .name("John")
                .surname("Doe")
                .email("john.doe@example.com")
                .createdAt(null)
                .updatedAt(null)
                .build();
    }

    @Test
    void testGetUser_Success() {
        // Arrange
        doNothing().when(authorizationHelperService).validateAccessToken(validToken);
        when(authorizationHelperService.getUserId(validToken)).thenReturn(userId);
        when(userRepository.findById(userId)).thenReturn(Optional.of(userEntity));
        when(userMapper.mapToDto(userEntity)).thenReturn(userResponse);

        // Act
        RetrieveUserResponse result = userService.getUser(validToken);

        // Assert
        assertNotNull(result);
        assertEquals(userId, result.id());
        assertEquals("John", result.name());
        assertEquals("Doe", result.surname());
        verify(userRepository).findById(userId);
        verify(userMapper).mapToDto(userEntity);
    }

    @Test
    void testGetUser_UserNotFound() {
        // Arrange
        doNothing().when(authorizationHelperService).validateAccessToken(validToken);
        when(authorizationHelperService.getUserId(validToken)).thenReturn(userId);
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        // Act & Assert
        NotFoundException exception = assertThrows(NotFoundException.class, () -> userService.getUser(validToken));

        // Assert
        assertEquals("User does not exist!", exception.getMessage());
    }

    @Test
    void testGetUser_TokenExpired() {
        // Arrange
        doThrow(new BadRequestException(Error.ERR_05.getErrorDescription(), Error.ERR_05.getErrorCode()))
                .when(authorizationHelperService).validateAccessToken(expiredToken);

        when(authorizationHelperService.getUserId(expiredToken)).thenReturn(userId);

        // Act & Assert
        BadRequestException exception = assertThrows(BadRequestException.class, () -> userService.getUser(expiredToken));

        // Assert
        assertEquals(Error.ERR_05.getErrorDescription(), exception.getMessage());
    }


    @Test
    void testDeleteUser_Success() {
        // Arrange
        doNothing().when(authorizationHelperService).validateAccessToken(validToken);
        when(authorizationHelperService.getUserId(validToken)).thenReturn(userId);
        when(userRepository.findById(userId)).thenReturn(Optional.of(userEntity));

        // Act
        userService.deleteUser(validToken);

        // Assert
        verify(msTransferClient).deleteAllAccountsByUser("Bearer " + validToken);
        verify(userRepository).delete(userEntity);
    }

    @Test
    void testDeleteUser_UserNotFound() {
        // Arrange
        doNothing().when(authorizationHelperService).validateAccessToken(validToken);
        when(authorizationHelperService.getUserId(validToken)).thenReturn(userId);
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        // Act & Assert
        NotFoundException exception = assertThrows(NotFoundException.class, () -> userService.deleteUser(validToken));

        assertEquals("User does not exist!", exception.getMessage());
    }

    @Test
    void testUpdateUserPassword_Success() {
        // Arrange
        UpdateUserRequest updateUserRequest = new UpdateUserRequest("new-password");
        doNothing().when(authorizationHelperService).validateAccessToken(validToken);
        when(authorizationHelperService.getUserId(validToken)).thenReturn(userId);
        when(userRepository.findById(userId)).thenReturn(Optional.of(userEntity));
        when(passwordEncoder.encode(updateUserRequest.password())).thenReturn("encoded-new-password");
        when(userRepository.save(userEntity)).thenReturn(userEntity);
        when(userMapper.mapToDto(userEntity)).thenReturn(userResponse);

        // Act
        RetrieveUserResponse result = userService.updateUserPassword(validToken, updateUserRequest);

        // Assert
        assertNotNull(result);
        assertEquals("encoded-new-password", userEntity.getPassword());
        verify(userRepository).save(userEntity);
        verify(userMapper).mapToDto(userEntity);
    }

    @Test
    void testUpdateUserPassword_UserNotFound() {
        // Arrange
        UpdateUserRequest updateUserRequest = new UpdateUserRequest("new-password");
        doNothing().when(authorizationHelperService).validateAccessToken(validToken);
        when(authorizationHelperService.getUserId(validToken)).thenReturn(userId);
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        // Act & Assert
        NotFoundException exception = assertThrows(NotFoundException.class, () -> userService.updateUserPassword(validToken, updateUserRequest));

        assertEquals("User does not exist!", exception.getMessage());
    }

    @Test
    void testUpdateUserPassword_TokenExpired() {
        // Arrange
        UpdateUserRequest updateUserRequest = new UpdateUserRequest("new-password");
        doThrow(new BadRequestException(Error.ERR_05.getErrorDescription(), Error.ERR_05.getErrorCode()))
                .when(authorizationHelperService).validateAccessToken(expiredToken);

        // Act & Assert
        BadRequestException exception = assertThrows(BadRequestException.class, () -> userService.updateUserPassword(expiredToken, updateUserRequest));

        // Assert
        assertEquals(Error.ERR_05.getErrorDescription(), exception.getMessage());
    }

}
