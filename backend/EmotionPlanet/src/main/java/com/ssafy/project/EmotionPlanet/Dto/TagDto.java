package com.ssafy.project.EmotionPlanet.Dto;

public class TagDto {

    private int no;
    private int feedNo;
    private String name;
    private int type;

    private int count; // 태그 검색 시 해당 태그가 포함된 피드 갯수 가져올때 사용.
    public int getCount() {
		return count;
	}
	public void setCount(int count) {
		this.count = count;
	}
	public TagDto() {
    }
    public TagDto(int no, int feedNo, String name, int type) {
        this.no = no;
        this.feedNo = feedNo;
        this.name = name;
        this.type = type;
    }

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

    public int getFeedNo() {
        return feedNo;
    }

    public void setFeedNo(int feedNo) {
        this.feedNo = feedNo;
    }
	@Override
	public String toString() {
		return "TagDto [no=" + no + ", feedNo=" + feedNo + ", name=" + name + ", type=" + type + ", count=" + count
				+ "]";
	}
    
    
}
