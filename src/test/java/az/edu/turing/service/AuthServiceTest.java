package az.edu.turing.service;

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
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static az.edu.turing.model.enums.Error.ERR_02;
import static az.edu.turing.model.enums.Error.ERR_03;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @Mock
    private UserRepository userRepository;

    @Mock
    private RedisTemplate<String, String> redisTemplate;

    @Mock
    private AuthenticationManager authenticationManager;

    @InjectMocks
    private AuthService authService;

    private UserEntity userEntity;

    @BeforeEach
    void setUp() {
        userEntity = UserEntity.builder()
                .id(1L)
                .name("John")
                .surname("Doe")
                .email("john.doe@example.com")
                .password("encoded_password")
                .build();
    }

    @Test
    void register_UserAlreadyExists_ThrowsBadRequestException() {
        RegisterUserRequest request = new RegisterUserRequest("John", "Doe", "john.doe@example.com", "password");

        when(userRepository.existsByEmail(request.email())).thenReturn(true);

        BadRequestException exception = assertThrows(BadRequestException.class, () -> authService.register(request));
        assertEquals(ERR_02.getErrorDescription(), exception.getMessage());
    }

    @Test
    void register_Success() {
        RegisterUserRequest request = new RegisterUserRequest("John", "Doe", "john.doe@example.com", "password");

        when(userRepository.existsByEmail(request.email())).thenReturn(false);
        when(passwordEncoder.encode(request.password())).thenReturn("encoded_password");
        when(userRepository.save(any(UserEntity.class))).thenReturn(userEntity);

        authService.register(request);

        verify(userRepository).save(any(UserEntity.class));
    }

    @Test
    void login_UserNotFound_ThrowsNotFoundException() {
        LoginUserRequest request = new LoginUserRequest("john.doe@example.com", "password");

        when(userRepository.findByEmail(request.email())).thenReturn(Optional.empty());

        NotFoundException exception = assertThrows(NotFoundException.class, () -> authService.login(request));
        assertEquals(ERR_03.getErrorDescription(), exception.getMessage());
    }

    @Test
    void login_RefreshTokenExists_ThrowsBadRequestException() {
        LoginUserRequest request = new LoginUserRequest("john.doe@example.com", "password");

        when(userRepository.findByEmail(request.email())).thenReturn(Optional.of(userEntity));
        when(redisTemplate.hasKey("refresh:" + userEntity.getId())).thenReturn(true);

        assertThrows(BadRequestException.class, () -> authService.login(request));

    }

//    @Test
//    void login_Success() {
//        LoginUserRequest request = new LoginUserRequest("john.doe@example.com", "password");
//
//        when(userRepository.findByEmail(request.email())).thenReturn(Optional.of(userEntity));
//        when(redisTemplate.hasKey("refresh:" + userEntity.getId())).thenReturn(false);
//        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);
//        when(jwtService.generateToken(anyString())).thenReturn("jwt_token");
//        when(jwtService.generateRefreshToken(anyString())).thenReturn("refresh_token");
//
//        JwtResponse response = authService.login(request);
//
//        assertNotNull(response);
//        assertEquals("jwt_token", response.accessToken());
//        assertEquals("refresh_token", response.refreshToken());
//        verify(redisTemplate).opsForValue().set("refresh:" + userEntity.getId(), "refresh_token", 1, TimeUnit.DAYS);
//    }


    @Test
    void logout_TokenExpired_ThrowsBadRequestException() {
        String accessToken = "expired_token";

        when(jwtService.isTokenExpired(accessToken)).thenReturn(true);

        assertThrows(BadRequestException.class, () -> authService.logout(1L, accessToken));
    }

    @Test
    void logout_Success() {
        String accessToken = "valid_token";

        when(jwtService.isTokenExpired(accessToken)).thenReturn(false);

        authService.logout(1L, accessToken);

        verify(redisTemplate).delete("refresh:" + 1L);
    }

    @Test
    void refresh_UserNotFound_ThrowsNotFoundException() {
        String token = "Bearer refresh_token";

        when(userRepository.findById(1L)).thenReturn(Optional.empty());

        assertThrows(NotFoundException.class, () -> authService.refresh(1L, token));
    }

//    @Test
//    void refresh_InvalidRefreshToken_ThrowsBadRequestException() {
//        String token = "Bearer invalid_token";
//
//        when(userRepository.findById(1L)).thenReturn(Optional.of(userEntity));
//        when(redisTemplate.opsForValue().get("refresh:" + userEntity.getId())).thenReturn("stored_token");
//        when(jwtService.isTokenExpired("invalid_token")).thenReturn(true);
//
//        assertThrows(BadRequestException.class, () -> authService.refresh(userEntity.getId(), token));
//    }
//
//    @Test
//    void refresh_Success() {
//        String token = "Bearer valid_refresh_token";
//
//        when(userRepository.findById(1L)).thenReturn(Optional.of(userEntity));
//        when(redisTemplate.opsForValue().get("refresh:" + userEntity.getId())).thenReturn("valid_refresh_token");
//        when(jwtService.isTokenExpired("valid_refresh_token")).thenReturn(false);
//        when(jwtService.generateToken(userEntity.getId().toString())).thenReturn("new_jwt_token");
//        when(jwtService.generateRefreshToken(userEntity.getId().toString())).thenReturn("new_refresh_token");
//
//        JwtResponse response = authService.refresh(userEntity.getId(), token);
//
//        assertNotNull(response);
//        assertEquals("new_jwt_token", response.accessToken());
//        assertEquals("new_refresh_token", response.refreshToken());
//        verify(redisTemplate).opsForValue().set("refresh:" + userEntity.getId(), "new_refresh_token", 1, TimeUnit.DAYS);
//    }
}
