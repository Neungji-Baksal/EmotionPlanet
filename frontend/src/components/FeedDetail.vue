<template>
	<div id="feed_detail" v-if="feed">
		<div id="img_container">
      <article id="img-box">
        <div id="uploaded-box">
          <transition-group id="carousel" :name="page > beforePage ? 'slide':'slide-reverse'">
            <img id="feedImg" v-for="(image, index) in feed.imgs" :key="index"
            class="uploadedImg" :src="image.imgLink" alt=""
            v-show="index+1 == page">
          </transition-group>
          <div id="pages">
            <span v-for="idx in feed.imgs.length" :key="idx" 
            :class="['page-num', {'here':idx==page}]" />
          </div>
          <span id="left" class="carousel-btn" @click="pagination(false)"/>
          <span id="right" class="carousel-btn" @click="pagination(true)"/>
        </div>
      </article>
      <!-- <div v-for="(img, idx) in feed.imgs" :key="idx"><img  id="feedImg" :src="img.imgLink" alt=""></div> -->
			<p class="overlay_content" >{{feed.authorDetail.nickname}}님은 <img id="planet_img" :src="require('@/assets/images/emotions/' + tmp.img)" style="width:1.2rem;height:1.2rem; margin-bottom:3px">을 여행 중</p>
		</div>
		<div id="feed_text">
			<div id="text_head">
				<img id="profile_image" :src="feed.authorDetail.profileImg" alt="">
				<div id="profile_info">
					<p id="username">{{feed.authorDetail.nickname }}</p>
					<p id="upload_date">{{ feed.date|dateChanger }}</p>
				</div>
				<div v-if="isMineFeed" id="setting">
					<i @click="onModalFeed" class="fas fa-ellipsis-v fa-2x" style="color:black"></i>
					<user-feed-setting v-if="isUserFeedSettingOpened" @cancel="isUserFeedSettingOpened=false"></user-feed-setting>
				</div>
        <div id="setting" v-else>
          <i class="fa-solid fa-x fa-lg" @click="goBack"></i>
        </div>
			</div>
			<hr>
			<div id="text_body">
        <div id="tags" >
          <p id="tag">#{{feed.tags[0].name}}행성 <img :src="require('@/assets/images/emotions/' + tmp.img)" alt="" style="width: 1.2rem; height: 1.2rem; margin-left: 0rem;"> &nbsp;</p> 
          <p id="tag" v-for="(tag, idx) in feed.tags.slice(1)" :key="idx">#{{tag["name"]}} &nbsp;</p>
        </div>
        <div>
					<p id="caption">{{feed.descr}}</p>
				</div>
        <br>
				<div id="comments">
					<div id="comment" v-for="(comment, idx) in commentsData" :key="idx">
						<img id="profile_image2" :src="comment.userRequestDto.profileImg" alt="">
						<p id="username2">{{comment.userRequestDto.nickname}}</p>
						<p id="user_comment">{{comment.descr}}</p>
						<div id="comment_setting">
              <i @click="onModalComment" class="fas fa-ellipsis-v" style="color:black; cursor:pointer;"></i>
							<!-- 댓글 하나하나에 유저데이터가 들어가서 해당 유저의 댓글이 지워져야 함-->							
							<!-- <comment-setting v-if="isCommentSettingOpened" @cancel="isCommentSettingOpened=false"></comment-setting> -->
						</div>
					</div>
				</div>
			</div>
			<hr>
			<div id="likes">
        <div id="heart" style="margin-right: 0.3rem;">
          <i class="far fa-heart fa-lg" :class="{'fas': this.feed.like}"  @click="like" style="cursor: pointer;"></i>
        </div>
        <p id="feed_likes" v-for="(like, idx) in feed.likes" :key="idx"></p>
        <p class="likes" style="cursor: pointer;" @click="likesList">{{feed.likes.length}} likes</p>
      </div>
			<hr>
			<div id="comment_write">
        <input id="comment-input" @keyup.enter="createComment" v-model.trim="commentContent" placeholder="댓글을 입력해 주세요."> 
        <img id="submit" @click="createComment" src="@/assets/images/icons/write.png" alt="" style="width:1.7rem;height:1.7rem;">
      </div>
		</div>
	</div>
</template>

<script>
import axios from 'axios';
const session = window.sessionStorage;

export default {
	data: function () {
		return {
      page:1,
      beforePage:1,
      isMineFeed:false,
      isMineComment:false,
			feed:null,
      comments:[],
      commentsData:[],
			commentContent:null,
			isCommentSettingOpened:false,
			isUserFeedSettingOpened: false,
      planetStyles: [
        { id: 1, name: '행복', img: "happy.png", color: '#6BD9E8' },
        { id: 2, name: '우울', img: "depressed.png", color: '#2A61F0' },
        { id: 3, name: '떠돌이', img: "space-station.png", color: '#C5D3DC' },
        { id: 4, name: '공포', img: "fear.png", color: '#ED5A8E' },
        { id: 5, name: '깜짝', img: "surprised.png", color: '#FEA95C' },
        { id: 6, name: '분노', img: "rage.png", color: '#FB5D38' },
      ],
		}
	},
	props:{
		feedNo:Number,
	},
  computed: {
    tmp: function () {
      let name = this.feed.tags[0].name
      let style = this.planetStyles.find(el => el.name === name) || {}
      return style
    }
  },
	methods: {
    goBack () {
      this.$router.push({name: 'Main'})
    },
    pagination(payload){
      this.beforePage = this.page
      if (this.page < this.feed.imgs.length && payload){
        this.page ++
      }
      else if (this.page > 1 && !payload){
        this.page --
      }
    },
    paginationByDot(target){
      let d
      if (target > this.page){
        d = true
      }
      else {
        d = false
      }
      for (let i=0;i<Math.abs(target-this.page);i++){
        setTimeout(() => {
          console.log(this.page, target, d)
          this.pagination(d)
        }, 1000 * i);
      }
    },
    getComment:function(commentNo){
      let headers = {
        'at-jwt-access-token': session.getItem('at-jwt-access-token'),
        'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
        };
        axios({
          method: 'get',
          url:`/api/comment/${commentNo}`,
          headers: headers,  // 넣는거 까먹지 마세요
          }).then((res) => {
            this.$store.dispatch('accessTokenRefresh', res) // store아닌곳에서
            this.commentsData.push(res.data)
            this.isMineComment=res.data.owner
            // this.getComments()
          }).catch((error) => {
            console.log(error);
          }).then(() => {
            console.log('댓글 하나 가져오기');
          });
        },
    getComments:function(){
      let headers = {
        'at-jwt-access-token': session.getItem('at-jwt-access-token'),
        'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
      };
      axios({
          method: 'get',
          url:`/api/comments/returnNo/${this.feedNo}`,
          headers: headers,  // 넣는거 까먹지 마세요
          }).then((res) => {
          this.$store.dispatch('accessTokenRefresh', res) // store아닌곳에서
          this.comments=res.data.reverse()
          this.commentsData=[]
          for (let i=0; i<this.comments.length; i++){
            const commentNo=this.comments[i]
            this.getComment(commentNo)
          }
          this.$store.commit('load', false)
          }).catch((error) => {
            console.log(error);
          }).then(() => {
            console.log('댓글 목록 가져오기');
          });
        },
    createComment:function(){
      const userdata = JSON.parse(session.getItem('userInfo')) 
      const commentItem={
          descr:this.commentContent,
          author:userdata.no,
          feedNo:this.feedNo
        }
      if(commentItem.descr){
        this.commentContent=null
        let headers = {
          'at-jwt-access-token': session.getItem('at-jwt-access-token'),
          'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
        };
        axios({
            method: 'post',
            url:'/api/comments',
            data: commentItem, // post 나 put에 데이터 넣어 줄때
            headers: headers,  // 넣는거 까먹지 마세요
          })
          .then((res) => {
             this.$store.dispatch('accessTokenRefresh', res) // store아닌곳에서
            //  console.log(res.data)
            //  console.log('댓글 다시 가져옴!!!!!!!!!!!!!!!!!!!!!!')
             this.getComments()
             let body = {
               receiver: this.feed.author,
               feedno: this.feedNo,
               commentno: res.data, // 이부분 백 수정하고 테스트해야함
             }
             this.$store.dispatch('comment',body)
          })
          .catch((error) => {
            console.log(error);
          })
          .then(() => {
            console.log('댓글 작성 완료');
          });

        
      }
      else{
        this.$store.commit('commentNeedContentModalActivate')
      }
    },
		getFeed:function(){
		let headers = {
			'at-jwt-access-token': session.getItem('at-jwt-access-token'),
			'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
			};
			axios({
				method: 'get',
				url:`/api/feed/${this.feedNo}`,
				headers: headers,  // 넣는거 까먹지 마세요
			}).then((res) => {
			this.$store.dispatch('accessTokenRefresh', res) // store아닌곳에서
			this.feed=res.data
			console.log('이건 피드 데이터', this.feed)
      this.getComments()
			this.isMineFeed=res.data.owner
      this.$store.commit('feedNumberForUpdate', this.feed.no)
			}).catch((error) => {
				console.log(error);
			}).then(() => {
				console.log('피드 하나 가져오기');
			}); 
		},
    // getLike(){
    //   let headers = {
		// 	'at-jwt-access-token': session.getItem('at-jwt-access-token'),
		// 	'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
		// 	};
		// 	axios({
		// 		method: 'get',
		// 		url:`/api/feeds/like/${this.feedNo}`,
		// 		headers: headers,  // 넣는거 까먹지 마세요
		// 	}).then((res) => {
		// 	this.$store.dispatch('accessTokenRefresh', res) // store아닌곳에서
		// 	console.log(res.data)
    //   this.feed.likes = res.data
		// 	}).catch((error) => {
		// 		console.log('좋아요 실패해따',error);
		// 	}).then(() => {
		// 		console.log('좋아요 하나 가져오기');
		// 	});
    // },
    like:function(){
      this.feed.like ? this.cancelLike(): this.doLike();
      this.feed.like= !this.feed.like;
    },
    doLike:function(){
		console.log(this.feedNo)
      let el = {
        receiver : this.feed.author,
        feedno : this.feedNo,
      }
      this.$store.dispatch('addfeedlike',el)
      // .then(() => this.getLike())
      this.getFeed()
    },
    cancelLike:function(){
      this.$store.dispatch('deletefeedlike',this.feedNo)
      // .then(() => this.getLike())
      this.getFeed()
    },
    onModalFeed:function(){
      this.onUserFeedSetting()
    },
    onModalComment:function(){
      this.onCommentSetting()
    },
		onCommentSetting:function(){
			this.$store.commit('commentSettingModalActivate')

		},
		onUserFeedSetting:function(){
			this.$store.commit('userFeedSettingModalActivate', this.feed.author)
	
		},
    likesList:function(){
       this.$store.commit('likesListActive',this.feed.likes)
       console.log(this.feed.likes)
    }
	},
  filters: {
    dateChanger(payload){
      const today = new Date();
      const timeValue = new Date(payload);

      const betweenTime = Math.floor((today.getTime() - timeValue.getTime()) / 1000 / 60);
      if (betweenTime < 1) return '방금전';
      if (betweenTime < 60) {
          return `${betweenTime}분전`;
      }

      const betweenTimeHour = Math.floor(betweenTime / 60);
      if (betweenTimeHour < 24) {
          return `${betweenTimeHour}시간전`;
      }

      const betweenTimeDay = Math.floor(betweenTime / 60 / 24);
      if (betweenTimeDay < 365) {
          return `${betweenTimeDay}일전`;
      }

      return `${Math.floor(betweenTimeDay / 365)}년전`;
    }
  },
	created(){
		this.getFeed()
    console.log(typeof(this.feedNo), this.feedNo)
		
	}
}
</script>

<style scoped>
.fas{
    color: crimson;
  }
#feed_detail {
	width: 70rem;
	height: 45rem;
	display: flex;
	justify-content: center;
	align-items: center;
	margin: auto;
	border: 3px solid rgb(94, 57, 179);
  background-color: white;
}
#img_container {
  position: relative;
  width: 65%;
  height: 100%;
}
#feedImg{
	width: 100%;
	height: 100%;
	border-right: 1.5px solid;
	border-left: none;
	border-top: none;
	border-bottom: none;
}
#feed_text {
  width: 45%;
	height: 100%;
	display:flex;
	flex-direction: column;
}
#text_head {
	display: flex;
	flex-direction: row;
	justify-content: left;
	align-items: center;
	height: 15%;
	margin-left: 1rem;
}
#profile_image {
	width: 4rem;
	height: 4rem;
	border-radius: 5vh;
	margin-right: 0.5rem;
}
#profile_info {
	padding-top:auto;
	padding-bottom: auto;
}
#username {
	font-weight: bold;
	margin: 0rem;
	font-size: 1.5rem;
}
#upload_date {
	text-align: left;
	font-size: 1rem;
	margin: 0rem;
}
#setting {
	margin-left:auto;
	margin-right: 1rem;
  cursor: pointer;
}
#text_body {
	height: 65vh;
	overflow: auto;
	margin-left: 0.4rem;
	margin-right: 0.4rem;
	margin-top: 0.5rem;
}
#caption {
	font-size: 1rem;
	text-align: left;
  margin: 0.4rem;
  font-weight: bold;
}
#tags {
	display: flex;
	flex-direction: row;
	flex-wrap: wrap;
}
#tag {
	color: blue;
	font-size: 0.9rem;
}
#comment {
	display: flex;
	flex-direction: row;
	justify-content: left;
	align-items: center;
	font-size: 1rem;
	margin-top: 0.5rem;
	margin-bottom: 0.5rem;
}
#profile_image2 {
  width: 3rem;
	height: 3rem;
	border-radius: 50%;
	margin-right: 0.5rem;
}
#username2 {
  font-weight: bold;
	margin: 0rem;
	font-size: 1.2rem;
}
#user_comment {
	margin-top:auto;
	margin-bottom: auto;
	margin-left: 0.5rem;
  font-size: 1rem;
}
#likes{
	display:flex;
	height: 5vh;
	margin-left: 0.4rem;
	margin-right: 0.4rem;
	margin-top: 0.5rem;
	justify-content: left;
	align-items: center;
}
button {
	border-style: none;
	color: blue;
	background-color: white;
	font-size: 0.7rem;
	margin-left: 0.5vh;

}
hr{
	margin: 0rem;
}
#like_count {
	font-weight: bold;
	font-size: 0.9rem;
	margin-top: auto;
	margin-bottom:auto;
}
.overlay_content {
	position: absolute;
	background-color: white;
	border-radius: 30px;
	top:95.5%;
  left:-0.5%;
	margin-left: 0.3rem;
  padding: 0.2rem;
  font-weight: bold;
}
#comment_setting {
  margin-left: auto;
  margin-right: 1rem;
}
#comment_write{
  height: 10%;
  position: relative;
}
#comment-input{
  width: 100%;
  border:0.2rem solid gainsboro;
  border-radius: 10px;
  outline: none;
  padding-right: 1.7rem;
  padding-left: 0.4rem;
  margin-top: 1rem;
}
#submit{
  position: absolute;
  left: 93%;
  top: 30%;
  cursor: pointer;
}
#uploaded-box {
    width: 100%;
    height: 100%;
    position: relative;
  }
  
.uploadedImg {
  width: 100%;
  /* aspect-ratio: 1/1;
  position: absolute; */
}
@keyframes slide-in {
  from { right: -100% }
  to { right: 0 }
}

@keyframes slide-out {
  from { right: 0 }
  to { right: 100% }
}
.slide-enter-active {
  animation: slide-in 1s ease;
}

.slide-leave-active {
  animation: slide-out 1s ease;
}

.slide-reverse-enter-active {
  animation: slide-out 1s ease reverse;
}

.slide-reverse-leave-active {
  animation: slide-in 1s ease reverse;
}
#pages {
  display: flex;
  flex-wrap: nowrap;
  justify-content: center;
  align-items: center;
  position: absolute;
  top: 95%;
  left: 50%;
  transform: translateX(-50%)
}

.page-num {
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background-color: #cccccc;
  margin: 0.75rem;
  cursor: pointer;
}
  #img-box {
  display: flex;
  flex-direction: column;
  width: 100%;
  height: 100%;
  justify-content: center;
  align-items: center;
}
.here {
  background-color: #777777;
}
#left {
  background-image: url('../assets/images/icons/left.png');
  left: 0%;
}

#right {
  background-image: url('../assets/images/icons/right.png');
  right: 0%;
}

#carousel {
  display: flex;
  align-items: center;
  width: 100%;
  height: 100%;
  position: relative;
  overflow: hidden;
}
.carousel-btn {
  background-size: cover;
  border: none;
  border-radius: 50%;
  opacity: 0.75;
  position: absolute;
  width: 2rem;
  height: 2rem;
  top: 50%;
  cursor: pointer;
}
</style>