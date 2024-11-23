package az.edu.turing.controller;


import az.edu.turing.auth.AuthorizationHelperService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1/auth/helper")
@RequiredArgsConstructor
@Tag(name = "Authentication Helper Controller API", description = "helper controller")
public class HelperController {

    private final AuthorizationHelperService authorizationHelperService;

    @PostMapping("/extract-token")
    public ResponseEntity<String> extractToken(@RequestHeader("Authorization") String authorizationHeader) {
        return ResponseEntity.ok().body(authorizationHelperService.extractToken(authorizationHeader));
    }

    @GetMapping("/user-id")
    public ResponseEntity<Long> getUserId(@RequestParam String accessToken) {
        return ResponseEntity.ok().body(authorizationHelperService.getUserId(accessToken));
    }

    @PostMapping("/validate-token")
    public void validateAccessToken(@RequestParam String accessToken) {
        authorizationHelperService.validateAccessToken(accessToken);
    }
}
