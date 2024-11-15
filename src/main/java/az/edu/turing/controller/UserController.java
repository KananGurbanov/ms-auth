package az.edu.turing.controller;

import az.edu.turing.auth.AuthorizationHelperService;
import az.edu.turing.model.dto.RestResponse;
import az.edu.turing.model.dto.request.UpdateUserRequest;
import az.edu.turing.model.dto.response.RetrieveUserResponse;
import az.edu.turing.service.UserService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1/users")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "User Controller API", description = "user controller")
public class UserController {

    private final UserService userService;
    private final AuthorizationHelperService authorizationHelperService;

    @GetMapping
    public ResponseEntity<RestResponse<RetrieveUserResponse>> getUserById(
            @RequestHeader("Authorization") String authHeader) {

        String token = authorizationHelperService.extractToken(authHeader);
        RetrieveUserResponse user = userService.getUser(token);

        RestResponse<RetrieveUserResponse> restResponse = RestResponse.<RetrieveUserResponse>builder()
                .data(user)
                .status("SUCCESS")
                .build();

        return ResponseEntity.ok(restResponse);
    }

    @PatchMapping
    public ResponseEntity<RestResponse<RetrieveUserResponse>> updatePassword(
            @RequestHeader("Authorization") String authHeader, @RequestBody UpdateUserRequest updateUserRequest) {

        String token = authorizationHelperService.extractToken(authHeader);
        RetrieveUserResponse user = userService.updateUserPassword(token, updateUserRequest);

        RestResponse<RetrieveUserResponse> restResponse = RestResponse.<RetrieveUserResponse>builder()
                .data(user)
                .status("SUCCESS")
                .build();

        return ResponseEntity.ok(restResponse);
    }

    @DeleteMapping
    public ResponseEntity<Void> deleteUser(
            @RequestHeader("Authorization") String authHeader) {

        String token = authorizationHelperService.extractToken(authHeader);
        log.info(token);
        userService.deleteUser(token);

        return ResponseEntity.noContent().build();
    }
}
