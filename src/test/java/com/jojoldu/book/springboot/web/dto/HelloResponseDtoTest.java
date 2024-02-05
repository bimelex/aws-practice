package com.jojoldu.book.springboot.web.dto;

import com.jojoldu.book.springboot.dto.HelloResponseDto;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class HelloResponseDtoTest {

    @Test
    public void lombok_test() {

        String name = "test";
        int amount = 10000;

        HelloResponseDto helloResponseDto = new HelloResponseDto(name, amount);

        assertEquals(helloResponseDto.getName(), name);
        assertEquals(helloResponseDto.getAmount(), amount);

    }

}