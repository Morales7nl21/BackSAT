package com.satdata.bdsat;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;

@SpringBootApplication
public class BdSatApplication {

	public static void main(String[] args) {
		SpringApplication.run(BdSatApplication.class, args);
	}

}
