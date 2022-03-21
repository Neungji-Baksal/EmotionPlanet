package com.ssafy.project.EmotionPlanet.Dto;

public class ImgDto {

    private int no;
    private int feedNo;
    private String imgName;
    private String imgLink;

    public ImgDto() {
    }

    public ImgDto(int no, int feedNo, String imgName, String imgLink) {
        this.no = no;
        this.feedNo = feedNo;
        this.imgName = imgName;
        this.imgLink = imgLink;
    }

    public int getNo() {
        return no;
    }

    public void setNo(int no) {
        this.no = no;
    }

    public int getFeedNo() {
        return feedNo;
    }

    public void setFeedNo(int feedNo) {
        this.feedNo = feedNo;
    }

    public String getImgName() {
        return imgName;
    }

    public void setImgName(String imgName) {
        this.imgName = imgName;
    }

    public String getImgLink() {
        return imgLink;
    }

    public void setImgLink(String imgLink) {
        this.imgLink = imgLink;
    }
}
