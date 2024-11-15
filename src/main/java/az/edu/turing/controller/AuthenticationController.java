package az.edu.turing.controller;

import az.edu.turing.auth.AuthorizationHelperService;
import az.edu.turing.model.dto.RestResponse;
import az.edu.turing.model.dto.request.LoginUserRequest;
import az.edu.turing.model.dto.request.RegisterUserRequest;
import az.edu.turing.model.dto.response.JwtResponse;
import az.edu.turing.service.AuthService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("api/v1/auth")
@Tag(name = "Authentication Controller API", description = "auth controller")
public class AuthenticationController {

    private final AuthService authService;
    private final AuthorizationHelperService authorizationHelperService;

    @PostMapping("/register")
    public ResponseEntity<Void> register(@RequestBody @Valid RegisterUserRequest request) {
        authService.register(request);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/login")
    public ResponseEntity<RestResponse<JwtResponse>> authenticate(@RequestBody @Valid LoginUserRequest request) {
        JwtResponse login = authService.login(request);
        RestResponse<JwtResponse> response = RestResponse.<JwtResponse>builder()
                .data(login)
                .status("SUCCESS")
                .build();
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String authorizationHeader) {
        String accessToken = authorizationHelperService.extractToken(authorizationHeader);
        authService.logout(accessToken);
        return ResponseEntity.ok("Logged out successfully");
    }

    @PostMapping("/refresh")
    public ResponseEntity<RestResponse<JwtResponse>> refresh(@RequestHeader("Authorization") String refreshToken) {
        String token = authorizationHelperService.extractToken(refreshToken);
        JwtResponse refresh = authService.refresh(token);
        RestResponse<JwtResponse> response = RestResponse.<JwtResponse>builder()
                .data(refresh)
                .status("SUCCESS")
                .build();
        return ResponseEntity.ok(response);
    }
}
