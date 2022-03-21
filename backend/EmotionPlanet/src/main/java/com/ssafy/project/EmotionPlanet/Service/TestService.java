package com.ssafy.project.EmotionPlanet.Service;

import java.util.List;

import com.ssafy.project.EmotionPlanet.Dto.TestDto;
import com.ssafy.project.EmotionPlanet.Dto.TestResultDto;

public interface TestService {
	 public List<TestDto> step1();
	 public List<TestDto> step2(List<TestDto> testDto);
	 public TestDto step3(List<TestDto> testDto);
}
