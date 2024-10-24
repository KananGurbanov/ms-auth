package az.edu.turing.service.impl;

import az.edu.turing.auth.JwtService;
import az.edu.turing.dao.entity.UserEntity;
import az.edu.turing.dao.repository.UserRepository;
import az.edu.turing.exceptions.NotFoundException;
import az.edu.turing.model.dto.request.LoginUserRequest;
import az.edu.turing.model.dto.response.JwtResponse;
import az.edu.turing.service.AuthService;
import az.edu.turing.token.RefreshToken;
import az.edu.turing.token.TokenRepository;
import az.edu.turing.token.TokenType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import static az.edu.turing.model.enums.Error.ERR_03;

@RequiredArgsConstructor
@Service
@Slf4j
public class AuthServiceImpl implements AuthService {
    private final TokenRepository tokenRepository;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;


    @Override
    public JwtResponse login(LoginUserRequest loginUserRequest) {
        UserEntity userEntity = userRepository.findByEmail(loginUserRequest.email())
                .orElseThrow(() -> new NotFoundException(ERR_03.getErrorDescription(), ERR_03.getErrorCode()));

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        userEntity.getId(),
                        loginUserRequest.password()
                )
        );

        var jwtToken = jwtService.generateToken(userEntity.getId().toString());
        var refreshToken = jwtService.generateRefreshToken(userEntity.getId().toString());

        saveUserToken(userEntity.getId(), refreshToken);
        return JwtResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    @Override
    public void logout(Long userId) {
        tokenRepository.deleteByUserId(userId);
    }

    private void saveUserToken(Long userId, String refreshToken) {
        var token = RefreshToken.builder()
                .token(refreshToken)
                .tokenType(TokenType.BEARER)
                .userId(userId)
                .build();
        tokenRepository.save(token);
    }

    @Override
    public JwtResponse refresh(Long userId) {
        userRepository.findById(userId)
                .orElseThrow(() -> new NotFoundException(ERR_03.getErrorCode(), ERR_03.getErrorDescription()));

        String newAccessToken = jwtService.generateToken(userId.toString());
        String newRefreshToken = jwtService.generateRefreshToken(userId.toString());

        RefreshToken refreshToken = tokenRepository.findByUserId(userId).orElseThrow();

        refreshToken.setToken(newRefreshToken);

        tokenRepository.save(refreshToken);

        return JwtResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .build();

    }

}
