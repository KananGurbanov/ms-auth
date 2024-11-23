package az.edu.turing.handler;

import az.edu.turing.exceptions.BadRequestException;
import az.edu.turing.exceptions.NotFoundException;
import feign.Response;
import feign.codec.ErrorDecoder;
import org.springframework.stereotype.Component;

@Component
public class FeignErrorDecoder implements ErrorDecoder {
    @Override
    public Exception decode(String s, Response response) {
        return switch (response.status()) {
            case 400 -> new BadRequestException("400", "Bad Request");
            case 404 -> new NotFoundException("404", "Record not found");
            default -> new Exception("Unknown error occurred. Status code: " + response.status());
        };
    }
}