package az.edu.turing.exceptions;

public class BadRequestException extends CustomException {

    public BadRequestException(String message, String code) {
        super(message, code);
    }
}
