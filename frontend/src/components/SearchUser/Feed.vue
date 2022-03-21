<template>
  <div id="feed">
    <div id="header">
      <section id="profile_image">
        <img :src="$store.state.searchUserInfo.profileImg" />
      </section>
      <div id="profile_content">
        <section id="username" style="font-size:2rem;">{{ this.$store.state.searchUserInfo.nickname }}</section>
        <section style="font-size:1.2rem;">{{ feed.date }}</section>
      </div>
      <div id="setting" style="z-index: 2;" v-if="isMine">
        <i @click="onSetting" class="fas fa-ellipsis-v"></i>
        <div id="detail" v-if="isOpend" style="" >
          <p style="margin-bottom:0; margin-top:1rem;">수정</p>
          <hr>
          <p @click="deleteComment">삭제</p>
        </div>
      </div>
    </div>
    <div id="post_image" style="z-index: 1;">
      <div id="my_img" v-for="(img, idx) in feed.imgs" :key="idx"><div><img :src="img.imgLink" alt=""></div></div>
      <!-- <img :src="post.postImage" alt="" v> -->
      <!-- <p class="overlay_content" >{{post.author}}님은 {{post.tag[0]}} <img id="planet_img" :src="require('@/assets/images/emotions/' + tmp.img)" style="width:1.2rem;height:1.2rem; margin-bottom:3px">에 있어요</p> -->
    </div>
    <div id="like">
      <div id="heart">
        <i class="far fa-heart fa-lg" :class="{'fas': this.feed.like}" @click="like"></i>
      </div>
       <p id="feed_likes" v-for="(like, idx) in feed.likes" :key="idx"></p>
      <p class="likes" v-if="feed.likes">{{feed.likes.length}} likes</p>
    </div>
    <div id="content">
      <div id="tag">
        <p id="my_tag" v-for="(tag, idx) in feed.tags" :key="idx">#{{tag["name"]}}</p>
      </div> 
        <p id="caption" style="font-size:1.4rem"><span style="font-weight:bold; margin-right:5px;">{{this.$store.state.searchUserInfo.nickname}}</span>{{feed.descr}}</p>
    </div>
    <comment-list :feedNo="feed.no"></comment-list>
  </div>
</template>

<script>
import CommentList from '@/components/MainPage/FeedTab/CommentList.vue';
import axios from 'axios';
const session = window.sessionStorage;

export default {
  components: { CommentList },
  name: "Feed",
  props: {
    feed: Object,
  },
  data(){
    return{
      // date:this.post.date.toLocaleDateString(),
      isMine:false,
      isOpend:false,
      posts:[],
      planetStyles: [
        { id: 1, name: '행복행성', img: "happy.png", color: '#6BD9E8' },
        { id: 2, name: '우울행성', img: "depressed.png", color: '#2A61F0' },
        { id: 3, name: '떠돌이행성', img: "space-station.png", color: '#C5D3DC' },
        { id: 4, name: '공포행성', img: "fear.png", color: '#ED5A8E' },
        { id: 5, name: '깜짝행성', img: "surprised.png", color: '#FEA95C' },
        { id: 6, name: '분노행성', img: "rage.png", color: '#FB5D38' },
      ]
    }
  },
   computed: {
    tmp: function () {
      const name = this.feed.planet
      const style = this.planetStyles.find(el => el.name === name) || {}
      return style
    }
  },
  methods: {
    onSetting:function(){
      if(this.isOpend){
        this.isOpend=false
      }else{
        this.isOpend=true
      }
    },
    like() {
      this.feed.like ? this.cancelLike(): this.doLike();
      this.feed.like= !this.feed.like;
    },
    doLike:function(){
      let el = {
        receiver : this.feed.author,
        feedno : this.feed.no,
      }
      console.log(this.feed)
      this.$store.dispatch('addfeedlike',el)
    },
    cancelLike:function(){
      this.$store.dispatch('deletefeedlike',this.feed.no)
    },
    
    // getComments:function(){
    //   let headers = {
    //     'at-jwt-access-token': session.getItem('at-jwt-access-token'),
    //     'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
    // };
    // axios({
    //     method: 'get',
    //     url:`/api/comments/returnNo/${this.post}`,
    //     headers: headers,  // 넣는거 까먹지 마세요
    //   }).then((res) => {
    //   this.$store.dispatch('accessTokenRefresh', res) // store아닌곳에서
    //   console.log('!!!!!!!!!!!!!!!!!!!')
    //   console.log(res.data)
    //   this.comments=res.data
    //   this.commentsList=res.data.slice(0,2)
    //   this.getComments()
    //   }).catch((error) => {
    //     console.log(error);
    //   }).then(() => {
    //     console.log('댓글 목록 가져오기');
    //   });
    // }
    
  },
  created(){
    let headers = {
        'at-jwt-access-token': session.getItem('at-jwt-access-token'),
        'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
    };
    axios({
        method: 'get',
        url:`/api/feed/${this.feed.no}`,
        headers: headers,  // 넣는거 까먹지 마세요
      }).then((res) => {
      this.$store.dispatch('accessTokenRefresh', res) // store아닌곳에서
      console.log('!!!!!!!!!!!!!!!!!!!')
      console.log(res.data)
      this.feed=res.data
      this.isMine=res.data.owner
      }).catch((error) => {
        console.log(error);
      }).then(() => {
        console.log('피드 하나 가져오기');
      });
    
  }
  
};
</script>

<style scoped>
  #setting{
    font-size: 2rem;
    margin-left: auto;
  }
  #content{
    text-align: left;
    margin:0rem 3rem;
    font-size: 1.2rem;
  }
  #tag{
    display:flex;
  }
  #like{
    display:flex;
    /* margin:0rem 3rem 0rem; */
    margin-left: 3rem;
    align-items: center;

  }
  .likes{
    margin-top:1rem;
    margin-left:5px;
    font-size: 1.2rem;
  }
  #profile_content{
    direction:column;
  }
  #feed{
    border: 3px solid  rgb(94, 57, 179);
    border-radius: 30px;
    margin:1rem;
  }
  #my_tag{
    color:rgb(37, 37, 201);
    margin-bottom:3px;
    font-size:1.2rem;
  }
  #header{
    display:flex;
    margin:1rem 3rem; 
  }
  #username{
    font-size: 1.5rem;
    font-weight: bold;
  }
  #profile_image{
    display: inline-flex;
    width: 4rem;
    height: 4rem; 
    border-radius: 70%;
    overflow:hidden;
  }
  #profile_image img{
    width: 4rem;
    height: 4rem;

  }
  .level-left{
    
    /* background-color: antiquewhite; */
  }
  #post_image img{
    width: 90vh;
    height: 90vh;
  }
  #post_image{
    position: relative;
    overflow: hidden;
    display: flex;
    justify-content: center;
    align-items: flex-end;
  }
  .overlay_content {
    position: absolute;
    padding: 0rem 1rem;
    margin-right:16rem;
    background-color: white;
    border-radius: 10px;
  }
  #detail{
    width: 8%;
    font-size: 20px;
    border:1px solid black;
    border-radius: 10px;
    text-align: center;
    display: flex;
    flex-direction:column;
    position: absolute;
    /* transform: translate(34rem,-10px); */
    background-color: white;
  }

</style>