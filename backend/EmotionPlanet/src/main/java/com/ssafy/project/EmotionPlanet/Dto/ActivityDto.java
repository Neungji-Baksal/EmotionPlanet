package com.ssafy.project.EmotionPlanet.Dto;

public class ActivityDto {
	private int no;
	private String title;
	private String imgLink;
	private int type;
	public int getNo() {
		return no;
	}
	public void setNo(int no) {
		this.no = no;
	}
	public String getTitle() {
		return title;
	}
	public void setTitle(String title) {
		this.title = title;
	}
	public String getImgLink() {
		return imgLink;
	}
	public void setImgLink(String imgLink) {
		this.imgLink = imgLink;
	}
	public int getType() {
		return type;
	}
	public void setType(int type) {
		this.type = type;
	}
	public ActivityDto() {}
	public ActivityDto(int no, String title, String imgLink, int type) {
		super();
		this.no = no;
		this.title = title;
		this.imgLink = imgLink;
		this.type = type;
	}
	@Override
	public String toString() {
		return "ActivityDto [no=" + no + ", title=" + title + ", imgLink=" + imgLink + ", type=" + type + "]";
	}
}
