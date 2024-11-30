package az.edu.turing.model.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Builder;

@Builder
public record UpdateUserRequest(

        @NotBlank
        String oldPassword,


        @NotBlank
        String newPassword) {
}
