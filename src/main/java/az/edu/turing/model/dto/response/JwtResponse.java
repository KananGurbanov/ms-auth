package az.edu.turing.model.dto.response;

import lombok.Builder;

@Builder
public record JwtResponse(
        String accessToken,
        String refreshToken) {
}
