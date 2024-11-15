package az.edu.turing.service;

import az.edu.turing.auth.AuthorizationHelperService;
import az.edu.turing.auth.JwtService;
import az.edu.turing.dao.entity.UserEntity;
import az.edu.turing.dao.repository.UserRepository;
import az.edu.turing.exceptions.BadRequestException;
import az.edu.turing.exceptions.NotFoundException;
import az.edu.turing.model.dto.request.LoginUserRequest;
import az.edu.turing.model.dto.request.RegisterUserRequest;
import az.edu.turing.model.dto.response.JwtResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static az.edu.turing.model.enums.Error.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class AuthServiceTest {

    @InjectMocks
    private AuthService authService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @Mock
    private UserRepository userRepository;

    @Mock
    private RedisService redisService;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private AuthorizationHelperService authorizationHelperService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void register_ShouldRegisterUserSuccessfully() {
        // Arrange
        RegisterUserRequest request = new RegisterUserRequest("John", "Doe", "john.doe@example.com", "password123");
        when(userRepository.existsByEmail(request.email())).thenReturn(false);
        when(passwordEncoder.encode(request.password())).thenReturn("encodedPassword");

        UserEntity savedUser = UserEntity.builder()
                .id(1L)
                .name(request.name())
                .surname(request.surname())
                .email(request.email())
                .password("encodedPassword")
                .build();
        when(userRepository.save(any(UserEntity.class))).thenReturn(savedUser);

        // Act
        authService.register(request);

        // Assert
        verify(userRepository).save(any(UserEntity.class));
    }

    @Test
    void register_ShouldThrowExceptionIfEmailExists() {
        // Arrange
        RegisterUserRequest request = new RegisterUserRequest("John", "Doe", "john.doe@example.com", "password123");
        when(userRepository.existsByEmail(request.email())).thenReturn(true);

        // Act & Assert
        BadRequestException exception = assertThrows(BadRequestException.class, () -> authService.register(request));
        assertEquals(ERR_02.getErrorDescription(), exception.getMessage());
    }

    @Test
    void login_ShouldReturnJwtResponseSuccessfully() {
        // Arrange
        LoginUserRequest request = new LoginUserRequest("john.doe@example.com", "password123");
        UserEntity userEntity = UserEntity.builder().id(1L).email(request.email()).password("encodedPassword").build();
        when(userRepository.findByEmail(request.email())).thenReturn(Optional.of(userEntity));
        when(redisService.tokenExists(userEntity.getId())).thenReturn(false);

        when(jwtService.generateToken("1")).thenReturn("accessToken");
        when(jwtService.generateRefreshToken("1")).thenReturn("refreshToken");

        // Act
        JwtResponse response = authService.login(request);

        // Assert
        assertNotNull(response);
        assertEquals("accessToken", response.accessToken());
        assertEquals("refreshToken", response.refreshToken());
        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(redisService).saveToken(userEntity.getId(), "refreshToken");
    }

    @Test
    void login_ShouldThrowExceptionIfTokenExists() {
        // Arrange
        LoginUserRequest request = new LoginUserRequest("john.doe@example.com", "password123");
        UserEntity userEntity = UserEntity.builder().id(1L).email(request.email()).build();
        when(userRepository.findByEmail(request.email())).thenReturn(Optional.of(userEntity));
        when(redisService.tokenExists(userEntity.getId())).thenReturn(true);

        // Act & Assert
        BadRequestException exception = assertThrows(BadRequestException.class, () -> authService.login(request));
        assertEquals(ERR_04.getErrorDescription(), exception.getMessage());
    }

    @Test
    void logout_ShouldDeleteTokenSuccessfully() {
        // Arrange
        String accessToken = "validAccessToken";
        when(authorizationHelperService.getUserId(accessToken)).thenReturn(1L);
        when(redisService.tokenExists(1L)).thenReturn(true);

        // Act
        authService.logout(accessToken);

        // Assert
        verify(redisService).deleteToken(1L);
    }

    @Test
    void logout_ShouldThrowExceptionIfTokenNotExists() {
        // Arrange
        String accessToken = "validAccessToken";
        when(authorizationHelperService.getUserId(accessToken)).thenReturn(1L);
        when(redisService.tokenExists(1L)).thenReturn(false);

        // Act & Assert
        NotFoundException exception = assertThrows(NotFoundException.class, () -> authService.logout(accessToken));
        assertEquals(ERR_07.getErrorDescription(), exception.getMessage());
    }

    @Test
    void refresh_ShouldReturnNewTokensSuccessfully() {
        // Arrange
        String refreshToken = "validRefreshToken";
        when(authorizationHelperService.getUserId(refreshToken)).thenReturn(1L);
        when(redisService.tokenExists(1L)).thenReturn(true);
        when(redisService.getToken(1L)).thenReturn(refreshToken);
        when(jwtService.isTokenExpired(refreshToken)).thenReturn(false);
        when(jwtService.generateToken("1")).thenReturn("newAccessToken");
        when(jwtService.generateRefreshToken("1")).thenReturn("newRefreshToken");

        // Act
        JwtResponse response = authService.refresh(refreshToken);

        // Assert
        assertNotNull(response);
        assertEquals("newAccessToken", response.accessToken());
        assertEquals("newRefreshToken", response.refreshToken());
        verify(redisService).updateToken(1L, "newRefreshToken");
    }

    @Test
    void refresh_ShouldThrowExceptionIfTokenIsInvalidOrExpired() {
        // Arrange
        String refreshToken = "invalidRefreshToken";
        when(authorizationHelperService.getUserId(refreshToken)).thenReturn(1L);
        when(redisService.tokenExists(1L)).thenReturn(true);
        when(redisService.getToken(1L)).thenReturn("anotherToken");

        // Act & Assert
        BadRequestException exception = assertThrows(BadRequestException.class, () -> authService.refresh(refreshToken));
        assertEquals(ERR_05.getErrorDescription(), exception.getMessage());
    }
}
