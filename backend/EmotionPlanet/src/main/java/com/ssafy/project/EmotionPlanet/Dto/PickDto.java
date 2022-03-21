package com.ssafy.project.EmotionPlanet.Dto;

import java.time.LocalDateTime;
import java.util.List;

public class PickDto {

    private int no;
    private int userNo;
    private int tagNo;
    private String name;
    private LocalDateTime date;
    private int type; //0 노래 1 영화 2 활동
    private String imgLink;

    private int likes;
    private boolean like;
    private boolean owner;

    List<Integer> contentsList;
    List<PickContentDto> contentsListData;

    public PickDto() {
    }

    public PickDto(int no, int userNo, int tagNo, String name, LocalDateTime date, int type) {
        this.no = no;
        this.userNo = userNo;
        this.tagNo = tagNo;
        this.name = name;
        this.date = date;
        this.type = type;
    }

    public int getNo() {
        return no;
    }

    public void setNo(int no) {
        this.no = no;
    }

    public int getUserNo() {
        return userNo;
    }

    public void setUserNo(int userNo) {
        this.userNo = userNo;
    }

    public int getTagNo() {
        return tagNo;
    }

    public void setTagNo(int tagNo) {
        this.tagNo = tagNo;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public LocalDateTime getDate() {
        return date;
    }

    public void setDate(LocalDateTime date) {
        this.date = date;
    }

    public int getType() {
        return type;
    }

    public void setType(int type) {
        this.type = type;
    }

    public boolean isOwner() {
        return owner;
    }

    public void setOwner(boolean owner) {
        this.owner = owner;
    }

    public boolean isLike() {
        return like;
    }

    public void setLike(boolean like) {
        this.like = like;
    }

    public int getLikes() {
        return likes;
    }

    public void setLikes(int likes) {
        this.likes = likes;
    }

    public List<Integer> getContentsList() {
        return contentsList;
    }

    public void setContentsList(List<Integer> contentsList) {
        this.contentsList = contentsList;
    }

    public String getImgLink() {
        return imgLink;
    }

    public void setImgLink(String imgLink) {
        this.imgLink = imgLink;
    }

    public List<PickContentDto> getContentsListData() {
        return contentsListData;
    }

    public void setContentsListData(List<PickContentDto> contentsListData) {
        this.contentsListData = contentsListData;
    }
}
//=======
//import java.util.List;
//
//public class PickDto {
//	private int no;
//	private int userNo;
//	private String nickname; // 찜록록 작성자 닉네임
//	private String name;
//	private String date;
//	private int tagNo;
//
//	private List<PickContentDto> pickcontents;
//
//	public List<PickContentDto> getPickcontents() {
//		return pickcontents;
//	}
//	public void setPickcontents(List<PickContentDto> pickcontents) {
//		this.pickcontents = pickcontents;
//	}
//	public String getNickname() {
//		return nickname;
//	}
//	public void setNickname(String nickname) {
//		this.nickname = nickname;
//	}
//
//	public int getNo() {
//		return no;
//	}
//	public void setNo(int no) {
//		this.no = no;
//	}
//	public int getUserNo() {
//		return userNo;
//	}
//	public void setUserNo(int userNo) {
//		this.userNo = userNo;
//	}
//	public String getName() {
//		return name;
//	}
//	public void setName(String name) {
//		this.name = name;
//	}
//	public String getDate() {
//		return date;
//	}
//	public void setDate(String date) {
//		this.date = date;
//	}
//	public int getTagNo() {
//		return tagNo;
//	}
//	public void setTagNo(int tagNo) {
//		this.tagNo = tagNo;
//	}
//	public PickDto() {}
//	public PickDto(int no, int userNo, String nickname, String name, String date, int tagNo, List<PickContentDto> pickcontents) {
//		super();
//		this.no = no;
//		this.userNo = userNo;
//		this.nickname = nickname;
//		this.name = name;
//		this.date = date;
//		this.tagNo = tagNo;
//		this.pickcontents = pickcontents;
//	}
//	@Override
//	public String toString() {
//		return "PickDto [no=" + no + ", userNo=" + userNo + ", nickname=" + nickname + ", name=" + name + ", date="
//				+ date + ", tagNo=" + tagNo + ", pickcontents=" + pickcontents + "]";
//	}
//}
//>>>>>>> 193100556e19fef710dc760d0845d4e85e570120
