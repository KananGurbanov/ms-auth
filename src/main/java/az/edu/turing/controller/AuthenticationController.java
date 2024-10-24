package az.edu.turing.controller;

import az.edu.turing.auth.AuthorizationHelperService;
import az.edu.turing.model.dto.request.LoginUserRequest;
import az.edu.turing.model.dto.response.JwtResponse;
import az.edu.turing.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("api/v1/auth")
public class AuthenticationController {
    private final AuthService authService;
    private final AuthorizationHelperService authorizationHelperService;

    @PostMapping("/login")
    public ResponseEntity<JwtResponse> authenticate(@RequestBody @Valid LoginUserRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String accessToken) {
        Long userId = authorizationHelperService.getUserId(accessToken);
        authService.logout(userId);
        return ResponseEntity.ok("Logged out successfully");
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtResponse> register(@RequestHeader("Authorization") String refreshToken) {
        Long userId = authorizationHelperService.getUserId(refreshToken);
        JwtResponse refresh = authService.refresh(userId);
        return ResponseEntity.ok(refresh);
    }
}
