package com.jojoldu.book.springboot.web;

import com.jojoldu.book.springboot.dto.HelloResponseDto;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController     // Json을 반환하는 Controller로 만들어 줌.
public class HelloController {

    @GetMapping(value = "/hello")
    public String Hello() {
        return "Hello";
    }

    @GetMapping(value = "/hello/dto")
    public HelloResponseDto HelloDto(@RequestParam("name") String name, @RequestParam("amount") int amount) {
        return new HelloResponseDto(name, amount);
    }
}
