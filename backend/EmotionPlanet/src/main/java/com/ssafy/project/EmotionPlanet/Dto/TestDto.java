package com.ssafy.project.EmotionPlanet.Dto;

public class TestDto {
	private int no;
	private String name;
	private int type;
	public int getNo() {
		return no;
	}
	public void setNo(int no) {
		this.no = no;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public int getType() {
		return type;
	}
	public void setType(int type) {
		this.type = type;
	}
	public TestDto() {}
	public TestDto(int no, String name, int type) {
		super();
		this.no = no;
		this.name = name;
		this.type = type;
	}
	@Override
	public String toString() {
		return "TestDto [no=" + no + ", name=" + name + ", type=" + type + "]";
	}
}