package az.edu.turing.clients;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.RequestHeader;

@FeignClient(name = "ms-transfer", url = "http://localhost:8082/api/v1/accounts")
public interface MsTransferClient {

    @DeleteMapping
    void deleteAllAccountsByUser(@RequestHeader("Authorization") String auth);
}
