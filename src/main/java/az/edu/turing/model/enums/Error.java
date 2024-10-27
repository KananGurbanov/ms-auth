package az.edu.turing.model.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum Error {
    ERR_01("ERR_01", "Account does not exist!"),
    ERR_02("ERR_02", "MailAddress already exists!"),
    ERR_03("ERR_03", "User does not exist!"),
    ERR_04("ERR_04", "Already logged in. Logout to login again!"),
    ERR_05("ERR_05", "Invalid or expired token!");

    private final String errorCode;
    private final String errorDescription;
}
