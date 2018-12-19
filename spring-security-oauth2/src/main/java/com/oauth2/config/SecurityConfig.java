package com.oauth2.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	@Override
	protected void configure(HttpSecurity http) {
		try {
			http.antMatcher("/**")
				.authorizeRequests()
				.antMatchers("/","/login")
				.permitAll()
				.anyRequest()
				.authenticated();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) {
		try {
			auth.inMemoryAuthentication().passwordEncoder(encoder()) //  Neu khong ma hoa mat khau thi chuong trinh se bao loi rang passwordEncoder null
//			.withUser("phamhung").password("12345").roles("USER")
//			.and()
//			.withUser("phamhung1").password("123").roles("ADMIN");
			.withUser("zone1").password("$2a$10$1S5I.Bwi.mC6772UXHmGbuRJg07zWieGjsFsrZfirx48C97EkUztG").roles("USER")
            .and()
            .withUser("zone2").password("$2a$10$1S5I.Bwi.mC6772UXHmGbuRJg07zWieGjsFsrZfirx48C97EkUztG").roles("USER")
            .and()
            .withUser("zone3").password("$2a$10$1S5I.Bwi.mC6772UXHmGbuRJg07zWieGjsFsrZfirx48C97EkUztG").roles("USER")
            .and()
            .withUser("zone4").password("$2a$10$1S5I.Bwi.mC6772UXHmGbuRJg07zWieGjsFsrZfirx48C97EkUztG").roles("USER")
            .and()
            .withUser("zone5").password("$2a$10$1S5I.Bwi.mC6772UXHmGbuRJg07zWieGjsFsrZfirx48C97EkUztGs").roles("USER");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	// Neu khong co se bao loi o phan autowire o ben web security
	@Bean
    public AuthenticationManager customAuthenticationManager() throws Exception {
        return authenticationManager();
    }
	// Ma hoa mat khau
	@Bean
	public BCryptPasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}
}
