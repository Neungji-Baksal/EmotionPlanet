package com.ssafy.project.EmotionPlanet;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

@SpringBootApplication
public class EmotionPlanetApplication {

	public static final String APPLICATION_LOCATIONS = "spring.config.location="
			+ "classpath:application.properties,"
			+ "classpath:aws.yml,"
			+ "classpath:security.yml";

	public static void main(String[] args) {
		new SpringApplicationBuilder(EmotionPlanetApplication.class)
				.properties(APPLICATION_LOCATIONS)
				.run(args);
//		SpringApplication.run(EmotionPlanetApplication.class, args);
	}

}
