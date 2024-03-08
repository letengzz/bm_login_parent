package com.hjc;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan("com.hjc.mapper")
public class BmLoginBackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(BmLoginBackendApplication.class, args);
	}

}
