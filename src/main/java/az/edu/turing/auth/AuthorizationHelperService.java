package az.edu.turing.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthorizationHelperService {
    private final JwtService jwtService;

    public Long getUserId(String auth) {
        final String jwt = auth.substring(7);
        final String userId = jwtService.extractUserId(jwt);
        return Long.parseLong(userId);
    }
}