package az.edu.turing.model.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

public record RegisterUserRequest(

        @NotBlank(message = "Name must not be empty")
        String name,

        @NotBlank(message = "Surname must not be empty")
        String surname,

        @Email(message = "Email is not valid")
        String email,

        @NotBlank
        String password){
}