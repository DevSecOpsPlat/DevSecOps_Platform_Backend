package com.backend.devsecopsplatform_backend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class DevSecOpsPlatformBackendApplication {

    public static void main(String[] args) {
        SpringApplication.run(DevSecOpsPlatformBackendApplication.class, args);
    }

}
