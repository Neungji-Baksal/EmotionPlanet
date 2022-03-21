package com.ssafy.project.EmotionPlanet.Dto;

import java.time.LocalDateTime;

public class CommentDto {

    private int no;
    private int feedNo;
    private String descr;
    private int author;
    private LocalDateTime date;

    private boolean owner;
    private UserRequestDto userRequestDto;

    public CommentDto() {
    }

    public CommentDto(int no, int feedNo, String descr, int author, LocalDateTime date) {
        this.no = no;
        this.feedNo = feedNo;
        this.descr = descr;
        this.author = author;
        this.date = date;
    }

    public int getNo() {
        return no;
    }

    public void setNo(int no) {
        this.no = no;
    }

    public int getAuthor() {
        return author;
    }

    public void setAuthor(int author) {
        this.author = author;
    }

    public LocalDateTime getDate() {
        return date;
    }

    public void setDate(LocalDateTime date) {
        this.date = date;
    }

    public int getFeedNo() {
        return feedNo;
    }

    public void setFeedNo(int feedNo) {
        this.feedNo = feedNo;
    }

    public String getDescr() {
        return descr;
    }

    public void setDescr(String descr) {
        this.descr = descr;
    }

    public boolean isOwner() {
        return owner;
    }

    public void setOwner(boolean owner) {
        this.owner = owner;
    }

    public UserRequestDto getUserRequestDto() {
        return userRequestDto;
    }

    public void setUserRequestDto(UserRequestDto userRequestDto) {
        this.userRequestDto = userRequestDto;
    }
}
