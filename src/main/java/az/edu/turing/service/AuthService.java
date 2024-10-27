package az.edu.turing.service;

import az.edu.turing.auth.JwtService;
import az.edu.turing.dao.entity.UserEntity;
import az.edu.turing.dao.repository.UserRepository;
import az.edu.turing.exceptions.BadRequestException;
import az.edu.turing.exceptions.NotFoundException;
import az.edu.turing.model.dto.request.LoginUserRequest;
import az.edu.turing.model.dto.request.RegisterUserRequest;
import az.edu.turing.model.dto.response.JwtResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Objects;
import java.util.concurrent.TimeUnit;

import static az.edu.turing.model.enums.Error.*;

@RequiredArgsConstructor
@Service
@Slf4j
public class AuthService {

    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final RedisTemplate<String, String> redisTemplate;
    private final AuthenticationManager authenticationManager;

    public void register(final RegisterUserRequest registerUserRequest) {
        if (userRepository.existsByEmail(registerUserRequest.email())) {
            throw new BadRequestException(ERR_02.getErrorDescription(), ERR_02.getErrorCode());
        }

        var user = UserEntity.builder()
                .name(registerUserRequest.name())
                .surname(registerUserRequest.surname())
                .email(registerUserRequest.email())
                .password(passwordEncoder.encode(registerUserRequest.password()))
                .build();
        var savedUser = userRepository.save(user);
        log.info("Registered user with id: {}", savedUser.getId());
    }

    public JwtResponse login(final LoginUserRequest loginUserRequest) {
        final UserEntity userEntity = userRepository.findByEmail(loginUserRequest.email())
                .orElseThrow(() -> new NotFoundException(ERR_03.getErrorDescription(), ERR_03.getErrorCode()));

        if (Boolean.TRUE.equals(redisTemplate.hasKey("refresh:" + userEntity.getId()))) {
            throw new BadRequestException(ERR_04.getErrorDescription(), ERR_04.getErrorCode());
        }

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        userEntity.getId(),
                        loginUserRequest.password()
                )
        );

        final var jwtToken = jwtService.generateToken(userEntity.getId().toString());
        final var refreshToken = jwtService.generateRefreshToken(userEntity.getId().toString());

        redisTemplate.opsForValue().set("refresh:" + userEntity.getId(), refreshToken, 1, TimeUnit.DAYS);

        return JwtResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public void logout(final Long userId, final String accessToken) {
        if (jwtService.isTokenExpired(accessToken)) {
            throw new BadRequestException(ERR_05.getErrorDescription(), ERR_05.getErrorCode());
        }
        redisTemplate.delete("refresh:" + userId);
    }

    public JwtResponse refresh(final Long userId, final String token) {
        userRepository.findById(userId)
                .orElseThrow(() -> new NotFoundException(ERR_03.getErrorCode(), ERR_03.getErrorDescription()));

        final String refreshToken = token.substring(7);

        final String storedRefreshToken = redisTemplate.opsForValue().get("refresh:" + userId);
        if (!Objects.equals(storedRefreshToken, refreshToken) || jwtService.isTokenExpired(refreshToken)) {
            throw new BadRequestException(ERR_05.getErrorDescription(), ERR_05.getErrorCode());
        }

        final String newAccessToken = jwtService.generateToken(userId.toString());
        final String newRefreshToken = jwtService.generateRefreshToken(userId.toString());
        redisTemplate.opsForValue().set("refresh:" + userId, newRefreshToken, 1, TimeUnit.DAYS);

        return JwtResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .build();
    }
}
