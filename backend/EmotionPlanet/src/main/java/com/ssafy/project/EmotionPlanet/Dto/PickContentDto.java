package com.ssafy.project.EmotionPlanet.Dto;

public class PickContentDto {

    private int no;
    private int pickNo;
    private String title;
    private String apiId;
    private String imgLink;
    private String descr;
    private String year;
    private String genre;
    private int type;
    private int targetNo;
    private String author;

    public PickContentDto() {
    }

    public PickContentDto(int no, int pickNo, String title, String imgLink, String descr, String year, String genre, int type, String author) {
        this.no = no;
        this.pickNo = pickNo;
        this.title = title;
        this.imgLink = imgLink;
        this.descr = descr;
        this.year = year;
        this.genre = genre;
        this.type = type;
        this.author = author;
    }

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

    public String getGenre() {
        return genre;
    }

    public void setGenre(String genre) {
        this.genre = genre;
    }

    public int getType() {
        return type;
    }

    public void setType(int type) {
        this.type = type;
    }

    public String getAuthor() {
        return author;
    }

    public void setAuthor(String author) {
        this.author = author;
    }

    public int getPickNo() {
        return pickNo;
    }

    public void setPickNo(int pickNo) {
        this.pickNo = pickNo;
    }

    public String getApiId() {
        return apiId;
    }

    public void setApiId(String apiId) {
        this.apiId = apiId;
    }

    public int getTargetNo() {
        return targetNo;
    }

    public void setTargetNo(int targetNo) {
        this.targetNo = targetNo;
    }

    @Override
    public String toString() {
        return "PickContentDto{" +
                "no=" + no +
                ", pickNo=" + pickNo +
                ", title='" + title + '\'' +
                ", apiId='" + apiId + '\'' +
                ", imgLink='" + imgLink + '\'' +
                ", descr='" + descr + '\'' +
                ", year='" + year + '\'' +
                ", genre='" + genre + '\'' +
                ", type=" + type +
                ", targetNo=" + targetNo +
                ", author='" + author + '\'' +
                '}';
    }
}