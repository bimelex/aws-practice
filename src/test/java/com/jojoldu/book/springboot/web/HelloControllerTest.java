package com.jojoldu.book.springboot.web;


import com.jojoldu.book.springboot.config.auth.SecurityConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(SpringExtension.class)              // JUnit에 내장된 실행자 외희 다른 실행자 실행 (Springboot 와 JUnit 연결)
@WebMvcTest(controllers = HelloController.class,
excludeFilters = {
        @ComponentScan.Filter(type= FilterType.ASSIGNABLE_TYPE, classes = SecurityConfig.class)
})        // Spring 여러 Annotatation 중 Contoller 만 테스트
public class HelloControllerTest {

    @Autowired
    private MockMvc mvc;

    @Test
    @WithMockUser(roles = "USER")
    public void Return_Hello() throws Exception {

        String hello = "Hello";

        mvc.perform( get("/hello") )         //  MockMvc 를 통해 Http Get 요청
                .andExpect(status().isOk())                  // 요청에 대한 HTTP Header Status 값 검증(isOK : 200)
                .andExpect( content().string(hello))     // 요청에 대한 Body Content 검증
        ;

    }

    @Test
    @WithMockUser(roles = "USER")
    public void Return_HelloDto() throws Exception{

        String name = "Hello";
        int amount = 10000;

        mvc.perform( get("/hello/dto")
                        .param("name", name)
                        .param("amount", String.valueOf(amount)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name", is(name)))
                .andExpect(jsonPath("$.amount", is(amount)));
    }

}
