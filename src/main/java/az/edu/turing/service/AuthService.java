package az.edu.turing.service;

import az.edu.turing.model.dto.request.LoginUserRequest;
import az.edu.turing.model.dto.response.JwtResponse;

public interface AuthService {
    JwtResponse login(LoginUserRequest loginUserRequest);

    void logout(Long id);

    JwtResponse refresh(Long userId);
}
