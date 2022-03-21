<template>
  <div id="comment" v-if="commentData">
    <img id="comment_img" :src="commentData.userRequestDto.profileImg" alt="">
    <p id="username">{{commentData.userRequestDto.nickname}} </p> 
    <p id="user_comment">{{commentData.descr}} </p>
    <div id="setting" v-if="isMine" style="cursor: pointer;">
      <i @click="onCommentSetting" id="comment_setting" class="fas fa-ellipsis-v"></i>
    </div>
  </div>
</template>

<script>
import axios from 'axios'
const session = window.sessionStorage;
export default {
  name:'Comment',
  props:{
      comment:Number
  },
  data(){
    return{
      isMine:false,
      commentData:null,
      isCommentSettingOpened:false,
    
    }
  },
  methods:{
    onCommentSetting:function(){
      this.$store.commit('commentSettingModalActivate',this.comment)
    },
  },
  created(){
    let headers = {
      'at-jwt-access-token': session.getItem('at-jwt-access-token'),
      'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
  };
  axios({
      method: 'get',
      url:`/api/comment/${this.comment}`,
      headers: headers,  // 넣는거 까먹지 마세요
    }).then((res) => {
    this.$store.dispatch('accessTokenRefresh', res) // store아닌곳에서
    console.log('!!!!!!!!!!!!!!!!!!!')
    console.log(res.data)
    this.commentData=res.data
    this.isMine=res.data.owner
    // this.getComments()
    }).catch((error) => {
      console.log(error);
    })
  },
}
</script>

<style scoped>
#comment {
  display: flex;
  margin-bottom: 0.5rem;
}
#comment_img{
  width: 2.5rem;
  height: 2.5rem; 
  border-radius: 50%;
  margin-right:0.4rem;
  margin-bottom: auto;
  margin-top: auto;
}
#username {
  font-size: 1.5rem;
  font-weight: bold;
  margin-bottom: auto;
  margin-top: auto;
  margin-right: 0.4rem;
  white-space: nowrap;
}
#user_comment{
  font-size: 1rem;
  margin-bottom: auto;
  margin-top: auto;
  word-break: break-all;
  margin-right: 0.3rem;
  
}
#setting {
  width: 1%;
  margin-left: auto;
  margin-top: auto;
  margin-bottom: auto;
}
</style>