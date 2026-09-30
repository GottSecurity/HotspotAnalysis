package com.example;

import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;

@HttpExchange("/accounts")
public interface AccountApi {
    @GetExchange("/{id}")
    String getAccount(String id);
}
