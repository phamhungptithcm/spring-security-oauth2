package com.oauth2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan({"com.oauth2.config"})
public class SpringSecurityOauth2Application {

	public static void main(String[] args) throws Exception{
		SpringApplication.run(SpringSecurityOauth2Application.class, args);
	}
}
