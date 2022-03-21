package com.ssafy.project.EmotionPlanet.Dto;

public class TestResultDto {
	private int happiness;
	private int depressed;
	private int neutrality;
	private int fear;
	private int surprise;
	private int anger;
	public int getHappiness() {
		return happiness;
	}
	public void setHappiness(int happiness) {
		this.happiness = happiness;
	}
	public int getDepressed() {
		return depressed;
	}
	public void setDepressed(int depressed) {
		this.depressed = depressed;
	}
	public int getNeutrality() {
		return neutrality;
	}
	public void setNeutrality(int neutrality) {
		this.neutrality = neutrality;
	}
	public int getFear() {
		return fear;
	}
	public void setFear(int fear) {
		this.fear = fear;
	}
	public int getSurprise() {
		return surprise;
	}
	public void setSurprise(int surprise) {
		this.surprise = surprise;
	}
	public int getAnger() {
		return anger;
	}
	public void setAnger(int anger) {
		this.anger = anger;
	}
	public TestResultDto() {}
	public TestResultDto(int happiness, int depressed, int neutrality, int fear, int surprise, int anger) {
		super();
		this.happiness = happiness;
		this.depressed = depressed;
		this.neutrality = neutrality;
		this.fear = fear;
		this.surprise = surprise;
		this.anger = anger;
	}
	@Override
	public String toString() {
		return "TestResultDto [happiness=" + happiness + ", depressed=" + depressed + ", neutrality=" + neutrality
				+ ", fear=" + fear + ", surprise=" + surprise + ", anger=" + anger + "]";
	}
}
