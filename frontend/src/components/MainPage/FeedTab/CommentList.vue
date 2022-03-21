<template>
  <div id="comments" v-if="comments">
    <div id="form-commentInfo">
      <div id="comment-count">댓글 
          <span id="count">{{comments.length}}</span>
      </div>
      <comment v-for="(comment,index) in this.commentsList"
      :comment="comment"
      :key="index">
      </comment>
      <p v-if="isShort" id="comment-more" @click="goToDetail">댓글 더보기</p>
      <div id="comment_write">
        <input id="comment-input" @keyup.enter="createComment" v-model.trim="commentContent" placeholder="댓글을 입력해 주세요."> 
        <img id="submit" @click="createComment" src="@/assets/images/icons/write.png" alt="" style="width:2rem;height:2rem; margin-bottom:3px; cursor: pointer;">
      </div>
    </div>
  </div>
</template>

<script>
import Comment from './Comment.vue'
import axios from 'axios';
import {mapState} from 'vuex'

const session = window.sessionStorage;

export default {
  components: { Comment },
  name:'CommentList',
  data:function(){
    return{
      comments:null,
      commentsList:[],
      commentContent:null,
      isShort:true,
      isAll:false,
      
    }
  },
  props:{
      feedNo:Number,
      feedAuthor:Number,
 
  },
 
  methods:{
    goToDetail:function(){
      this.isShort=false
      this.$router.push({name:'FeedDetail', params:{feedNo:this.feedNo}})

    },
    forceRerender(){
      this.getComments()
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
      this.commentsList=this.comments.slice(0,2)
      console.log('댓글이 갱신됐슴다!!!!!!!!!!!!!!!!!!!', this.comments)
      })
      .catch((error) => {
        console.log(error);
      })
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
             console.log(res.data)
             console.log('댓글 다시 가져옴!!!!!!!!!!!!!!!!!!!!!!')
             this.getComments()
             let body = {
               receiver: this.feedAuthor,
               feedno: this.feedNo,
               commentno: res.data,
             }
             this.$store.dispatch('comment',body)
          })
          .catch((error) => {
            console.log(error);
          })
          .then(() => {
            console.log('댓글 작성 완료 코멘트 리스트');
          });
      }
      else{
        // alert('내용을 채워주세요')
        this.$store.commit('commentNeedContentModalActivate')
      }
    },
  },
  computed: {
    ...mapState([
      'commentDeleted'
    ])
  },
  watch: {
    commentDeleted: function () {
      const idx = this.comments.indexOf(this.commentDeleted)
      console.log('지워지는 값', idx)
      if (idx > -1) {
        this.$emit('delete-comment')
      } 
    }
  },
  created(){
    this.getComments()
    console.log('댓글프롭', this.feedNo, typeof(this.feedNo))
  },
}
</script>

<style scoped>
#submit{
  border-style: none;
}
#comment_write{
  border:0.2rem solid gainsboro;
  border-radius: 10px;
  margin-bottom:1rem;
}
#comments{
  text-align: left;
  margin:0rem 1rem;
}
#comment-count{
  color:#777777;
  font-size:1.2rem;
  margin-top: 0.5rem;
  margin-bottom: 0.5rem;
}
#comment-input{
  width: 93%;
  padding:3px;
  height: 100%;
  margin-left:5px;
  border-style:none;
  margin-bottom: 0;
  outline: none;
  font-size: 1.5rem;
}
#comment-more{
  margin-top: 1rem;
  font-size: 1.2rem;
  color:#777777;
  cursor: pointer;
}

</style>