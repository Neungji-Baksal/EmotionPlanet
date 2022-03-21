package com.ssafy.project.EmotionPlanet.Dto;

public class MovieDto {
	private int no;
	private String title;
	private String descr;
	private String year;
	private String imgLink;
	private String genre;
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
	public String getDescr() {
		return descr;
	}
	public void setDescr(String descr) {
		this.descr = descr;
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
	public String getGenre() {
		return genre;
	}
	public void setGenre(String genre) {
		this.genre = genre;
	}
	public MovieDto() {}
	public MovieDto(int no, String title, String descr, String year, String imgLink, String genre) {
		super();
		this.no = no;
		this.title = title;
		this.descr = descr;
		this.year = year;
		this.imgLink = imgLink;
		this.genre = genre;
	}
	@Override
	public String toString() {
		return "MovieDto [no=" + no + ", title=" + title + ", descr=" + descr + ", year=" + year + ", imgLink="
				+ imgLink + ", genre=" + genre + "]";
	}
}