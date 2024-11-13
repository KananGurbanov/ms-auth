package az.edu.turing.controller;

import az.edu.turing.auth.AuthorizationHelperService;
import az.edu.turing.model.dto.RestResponse;
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

        Long userId = authorizationHelperService.getUserId(authHeader);

        RetrieveUserResponse user = userService.getUser(userId);

        RestResponse<RetrieveUserResponse> restResponse = RestResponse.<RetrieveUserResponse>builder()
                .data(user)
                .status("SUCCESS")
                .build();

        return ResponseEntity.ok(restResponse);
    }
}
