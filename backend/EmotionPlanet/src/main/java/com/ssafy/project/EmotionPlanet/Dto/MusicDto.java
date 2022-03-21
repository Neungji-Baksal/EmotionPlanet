package com.ssafy.project.EmotionPlanet.Dto;

public class MusicDto {
	private String artist;
	private String title;
	private String year;
	private String imgLink;
	public String getArtist() {
		return artist;
	}
	public void setArtist(String artist) {
		this.artist = artist;
	}
	public String getTitle() {
		return title;
	}
	public void setTitle(String title) {
		this.title = title;
	}
	public String getYear() {
		return year;
	}
	public void setYear(String year) {
		this.year = year;
	}
	public String getImgLink() {
		return imgLink;
	}
	public void setImgLink(String imgLink) {
		this.imgLink = imgLink;
	}
	public MusicDto() {}
	public MusicDto(String artist, String title, String year, String imgLink) {
		super();
		this.artist = artist;
		this.title = title;
		this.year = year;
		this.imgLink = imgLink;
	}
	
	@Override
	public String toString() {
		return "MusicDto [artist=" + artist + ", title=" + title + ", year=" + year + ", imgLink=" + imgLink + "]";
	}
}
