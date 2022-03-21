package com.ssafy.project.EmotionPlanet.Service;

import com.ssafy.project.EmotionPlanet.Dao.*;
import com.ssafy.project.EmotionPlanet.Dto.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.ArrayList;
import java.util.List;

@Service
public class FeedServiceImpl implements FeedService{

    @Autowired
    FeedDao feedDao;

    @Autowired
    CommentDao commentDao;

    @Autowired
    TagDao tagDao;

    @Autowired
    ImgDao imgDao;

    @Autowired
    UserDao userDao;

    @Autowired
    S3Dao s3Dao;

    @Autowired
    TagService tagService;

    @Autowired
    S3Service s3Service;

    @Override
    public List<FeedDto> list(int no) {

        List<FeedDto> feeds = feedDao.list(no);
        for(FeedDto feed : feeds){
            List<CommentDto> comments = commentDao.list(feed.getNo());
            List<TagDto> tags = tagDao.list(feed.getNo());
            List<ImgDto> imgs = imgDao.list(feed.getNo());
            feed.setComments(comments);
            feed.setTags(tags);
            feed.setImgs(imgs);
        }

        return feeds;
    }

    @Override
    public List<Integer> listReturnNo(int no) {

        List<FeedDto> feeds = feedDao.list(no);
        List<Integer> numbers = new ArrayList<>();

        for (FeedDto feedDto : feeds) {
            numbers.add(feedDto.getNo());
        }

        return numbers;
    }

    @Override
    public List<FeedDto> myList(int userNo, int myNo) {

        List<FeedDto> feeds = feedDao.myList(userNo);
        for(FeedDto feed : feeds){
            List<CommentDto> comments = commentDao.list(feed.getNo());
            List<TagDto> tags = tagDao.list(feed.getNo());
            List<ImgDto> imgs = imgDao.list(feed.getNo());
            UserDto user = userDao.userSelect(feed.getAuthor());
            UserRequestDto userDetail = new UserRequestDto(user.getNo(), user.getNickname(), user.getProfileImg());
            if(myNo == feed.getAuthor()) feed.setOwner(true);
            if(feedDao.liking(myNo, feed.getNo()) == 1) feed.setLike(true);
            else feed.setLike(false);
            feed.setComments(comments);
            feed.setTags(tags);
            feed.setImgs(imgs);
            feed.setAuthorDetail(userDetail);

            List<UserRequestDto> follow = feedDao.likeListFollow(feed.getAuthor(), feed.getNo());
            List<UserRequestDto> unfollow = feedDao.likeListUnFollow(feed.getAuthor(), feed.getNo());
            List<UserRequestDto> sum = new ArrayList<>();
            for (UserRequestDto user1 : follow) {
                sum.add(user1);
            }
            for (UserRequestDto user1 : unfollow) {
                sum.add(user1);
            }
            feed.setLikes(sum);
        }

        return feeds;
    }

    @Override
    public List<Integer> myListReturnNo(int no) {

        List<FeedDto> feeds = feedDao.myList(no);
        List<Integer> numbers = new ArrayList<>();

        for (FeedDto feedDto : feeds) {
            numbers.add(feedDto.getNo());
        }

        return numbers;
    }

    @Override
    public FeedDto read(int no, int userNo) {

        FeedDto feed = feedDao.read(no);
        List<CommentDto> comments = commentDao.list(feed.getNo());
        List<TagDto> tags = tagDao.list(feed.getNo());
        List<ImgDto> imgs = imgDao.list(feed.getNo());
        UserDto user = userDao.userSelect(feed.getAuthor());
        UserRequestDto userDetail = new UserRequestDto(user.getNo(), user.getNickname(), user.getProfileImg());
        if(userNo == feed.getAuthor()) feed.setOwner(true);
        if(feedDao.liking(userNo, feed.getNo()) == 1) feed.setLike(true);
        else feed.setLike(false);
        feed.setComments(comments);
        feed.setTags(tags);
        feed.setImgs(imgs);
        feed.setAuthorDetail(userDetail);
        return feed;

    }

    @Override
    public int write(FeedDto feedDto) {

        int result = feedDao.write(feedDto);
        System.out.println("피드번호 : " + feedDto.getNo());
        if(feedDto.getNo() != 0){

            for (TagDto tag : feedDto.getTags()) {
                tag.setFeedNo(feedDto.getNo());
                tagService.create(tag);
            }

            return feedDto.getNo();
        } else return result;
    }

    @Override
    public int update(FeedDto feedDto, int type) {

        List<ImgDto> dbImg = imgDao.list(feedDto.getNo());
        List<TagDto> dbTag = tagDao.list(feedDto.getNo());

        if(type == 0) {
            for (ImgDto img : dbImg) {
                System.out.println("파일명 : " + img.getImgName());
                s3Dao.deleteByNo(img.getNo());
            }
            for (ImgDto img : feedDto.getImgs()) {
                imgDao.relation(img.getNo(), feedDto.getNo());
            }
        }else {
            for (ImgDto img : feedDto.getImgs()) {
                imgDao.relationDelete(img.getNo(), feedDto.getNo());
                imgDao.relation(img.getNo(), feedDto.getNo());
            }
        }

        for(TagDto tagDto : dbTag){
            tagDao.deleteRelation(tagDto.getNo(), feedDto.getNo());
        }


        for (TagDto tag : feedDto.getTags()) {
            tag.setFeedNo(feedDto.getNo());
            tagService.create(tag);
        }

        return feedDao.update(feedDto);
    }

    @Override
    public int delete(int no) {

        List<CommentDto> comments = commentDao.list(no);
        List<ImgDto> imgs = imgDao.list(no);
        List<TagDto> tags = tagDao.list(no);
        for(CommentDto comment : comments){
            commentDao.delete(comment.getNo());
        }
        for(ImgDto img : imgs){
            s3Dao.deleteByNo(img.getNo());
        }
        for(TagDto tag : tags){
            tagDao.deleteRelation(tag.getNo(), no);
        }

        return feedDao.delete(no);
    }

    @Override
    public List<UserRequestDto> likeList(int feedNo) {
        FeedDto feedDto = feedDao.read(feedNo);
        int userNo = feedDto.getAuthor();
        List<UserRequestDto> follow = feedDao.likeListFollow(userNo, feedNo);
        List<UserRequestDto> unfollow = feedDao.likeListUnFollow(userNo, feedNo);

        List<UserRequestDto> sum = new ArrayList<>();
        for (UserRequestDto user : follow) {
            sum.add(user);
        }
        for (UserRequestDto user : unfollow) {
            sum.add(user);
        }
        return sum;
    }

    @Override
    public int like(int userNo, int feedNo) {
        return feedDao.like(userNo, feedNo);
    }

    @Override
    public int unlike(int userNo, int feedNo) {
        return feedDao.unlike(userNo, feedNo);
    }

    @Override
    public int connect(String targetNo, List<Integer> imgNoList) {

        int result = 0;
        for (Integer imgNo : imgNoList) {
            result = feedDao.connect(targetNo, imgNo);
        }

        return result;
    }
}
