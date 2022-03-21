package com.ssafy.project.EmotionPlanet.Dto;

import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.util.List;

public class FeedDto {

    private int no;
    private String descr; //내용
    private int author;
    private List<TagDto> tags;
    private LocalDateTime date;

    private List<CommentDto> comments;
    private List<UserRequestDto> likes;
    private List<ImgDto> imgs;
    private List<MultipartFile> multipartFile;

    private UserRequestDto authorDetail;
    private boolean like = false;
    private boolean owner = false;


    public int getNo() {
		return no;
	}
	public void setNo(int no) {
		this.no = no;
	}
	public String getDescr() {
		return descr;
	}
	public void setDescr(String descr) {
		this.descr = descr;
	}
	public int getAuthor() {
		return author;
	}
	public void setAuthor(int author) {
		this.author = author;
	}
	public List<TagDto> getTags() {
		return tags;
	}
	public void setTags(List<TagDto> tags) {
		this.tags = tags;
	}
	public LocalDateTime getDate() {
		return date;
	}
	public void setDate(LocalDateTime date) {
		this.date = date;
	}
	public List<CommentDto> getComments() {
		return comments;
	}
	public void setComments(List<CommentDto> comments) {
		this.comments = comments;
	}

	public List<UserRequestDto> getLikes() {
		return likes;
	}

	public void setLikes(List<UserRequestDto> likes) {
		this.likes = likes;
	}

	public List<ImgDto> getImgs() {
		return imgs;
	}
	public void setImgs(List<ImgDto> imgs) {
		this.imgs = imgs;
	}
	public List<MultipartFile> getMultipartFile() {
		return multipartFile;
	}
	public void setMultipartFile(List<MultipartFile> multipartFile) {
		this.multipartFile = multipartFile;
	}
	public UserRequestDto getAuthorDetail() {
		return authorDetail;
	}
	public void setAuthorDetail(UserRequestDto authorDetail) {
		this.authorDetail = authorDetail;
	}
	public boolean isLike() {
		return like;
	}
	public void setLike(boolean like) {
		this.like = like;
	}
	public boolean isOwner() {
		return owner;
	}
	public void setOwner(boolean owner) {
		this.owner = owner;
	}
	public FeedDto() {}
	  public FeedDto(int no, String descr, int author, LocalDateTime date) {
	        this.no = no;
	        this.descr = descr;
	        this.author = author;
	        this.date = date;
	    }
	public FeedDto(int no, String descr, int author, List<TagDto> tags, LocalDateTime date,
			List<CommentDto> comments, List<UserRequestDto> likes, List<ImgDto> imgs, List<MultipartFile> multipartFile,
			UserRequestDto authorDetail, boolean like, boolean owner) {
		super();
		this.no = no;
		this.descr = descr;
		this.author = author;
		this.tags = tags;
		this.comments = comments;
		this.likes = likes;
		this.imgs = imgs;
		this.multipartFile = multipartFile;
		this.authorDetail = authorDetail;
		this.like = like;
		this.owner = owner;
	}
	@Override
	public String toString() {
		return "FeedDto [no=" + no + ", descr=" + descr + ", author=" + author + ", tags=" + tags + ", date=" + date
				+ ", comments=" + comments + ", likes=" + likes + ", imgs=" + imgs
				+ ", multipartFile=" + multipartFile + ", authorDetail=" + authorDetail + ", like=" + like + ", owner="
				+ owner + "]";
	}
}
