package com.hjc;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootTest
class BmLoginBackendApplicationTests {

	@Test
	void contextLoads() {
		//生成密码
		String encode = new BCryptPasswordEncoder().encode("123456");
		System.out.println("encode = " + encode);

	}

}
