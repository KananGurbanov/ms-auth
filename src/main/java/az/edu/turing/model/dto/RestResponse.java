package az.edu.turing.model.dto;

import lombok.Builder;

@Builder
public record RestResponse<T>(

        String status,
        T data) {
}
