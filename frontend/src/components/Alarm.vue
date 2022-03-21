<template>
  <div id="alarm_body">
    <div id="triangle"></div>
    <section id="alarm_header">
      <div id="title">
        <p>알림</p>
      </div>
    </section>
    <section id="alarm_content">
      <!-- alarm.alarmcheck = 0 이면 안 읽은 알람, 1이면 읽은 알람 -->
      <div id="results" v-if="this.$store.state.alarm.length !== 0">
        <div v-for="(result, index) in this.$store.state.alarm.slice(0, 21)"
        :key="index" :id="result.readcheck == 0 ? 'unchecked' : 'checked'">
          <!-- 팔로우 -->
          <div id="type_follow" v-if="result.type == 1" @click="follow(result.sender)">
            <img :src="result.senderImg" alt="" id="user">
            <div id="search">
              <span id="content">{{ result.senderNickname }}님이 회원님을</span>
              <span id="content">팔로우하기 시작했습니다.</span>
            </div>
          </div>
          <!-- 댓글 -->
          <div id="type_comment" v-if="result.type == 2" @click="feed(result.feedno)">
            <img :src="result.senderImg" alt="" id="user">
            <div id="search">
              <span id="content">{{ result.senderNickname }}님이 회원님의</span>
              <span id="content">이야기에 댓글을 달았습니다.</span>
            </div>
          </div>
          <!-- 피드 좋아요 -->
          <div id="type_feedlike" v-if="result.type == 3" @click="feed(result.feedno)">
            <img :src="result.senderImg" alt="" id="user">
            <div id="search">
              <span id="content">{{ result.senderNickname }}님이 회원님의</span>
              <span id="content">이야기를 좋아합니다.</span>
            </div>
          </div>
          <!-- 찜목록 좋아요 -->
          <div id="type_picklike" v-if="result.type == 4">
            <img :src="result.senderImg" alt="" id="user">
            <div id="search">
              <span id="content">{{ result.senderNickname }}님이 회원님의</span>
              <span id="content">보물상자를 좋아합니다.</span>
            </div>
          </div>
        </div>
      </div>
      <div v-else id="no_result">
        <img id="nothing" src="@/assets/images/etc/alien.png" alt="">
        <h3>알림이 없어요...</h3>
      </div> 
    </section>
    <section id="alarm_footer">
      <button @click="cancel">닫기</button>
    </section>
    <div id="other-side" @click="cancel"></div>
  </div>
</template>

<script>

export default {
  name: 'Alarm',
  
  data() {
    return {
      
    }
  },
  methods: {
    cancel() {
      this.$store.dispatch('readAlarm', this.$store.state.userInfo.no)
      this.$emit('cancelAlarm')
      // console.log("여기가 알림 닫는곳")
      // console.log(this.$store.state.searchUserNo)
      // console.log(this.$store.state.searchUserInfo)
    },
     async follow(el) {
      this.$store.state.searchUserNo = el
      await this.$store.dispatch('userSelect', el)
      await this.$store.dispatch('userfollowdate', el)
      this.$store.dispatch('readAlarm', this.$store.state.userInfo.no)
      // await this.$store.dispatch("searchUserFeed", this.$store.state.searchUserNo)
      this.$router.push({ path: `/user/${el}/feed` })
    },
    feed(el){
      this.$store.dispatch('readAlarm', this.$store.state.userInfo.no)
      console.log(el)
       this.$router.push({name:'FeedDetail', params:{feedNo:el}})
       window.location.reload()
    },
  },
  computed: {
    isShow(){
      return this.$store.state.navActive[3]
    }
  }
}
</script>

<style scoped>
  #alarm_body {
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    background-color: white;
    /* overflow-y: scroll; */
  }
  #triangle {
    width: 0px;
    height: 0px;
    border-bottom: 18px solid gainsboro;
    border-left: 30px solid transparent;
    border-right: 30px solid transparent;
    position: absolute;
    top: -5.2%;
    right: 41%; 
  }
  #alarm_header {
    z-index: 10;
    display: flex;
    justify-content: center;
    align-items: center;
    background-color: white;
    width: 100%;
    min-width: 300px;
    height: 10%;
    min-height: 55px;
    border-radius: 10px 10px 0 0;
    border-top: 0.15rem solid gainsboro;
    border-left: 0.15rem solid gainsboro;
    border-right: 0.15rem solid gainsboro;
    position: relative; 
  }
  
  #alarm_content {
    display: flex;
    justify-content: center;
    background-color: white !important;
    /* margin-top: 1030px; */
    width: 100%;
    min-width: 300px;
    height: 80%;
    min-height: 300px;
    border: 0.15rem solid gainsboro;
    /* overflow-y: scroll; */
  }
  
  #alarm_footer {
    display: flex;
    justify-content: center;
    background-color: white;
    width: 100%;
    min-width: 300px;
    height: 10%;
    min-height: 55px;
    border-bottom: 0.15rem solid gainsboro;
    border-left: 0.15rem solid gainsboro;
    border-right: 0.15rem solid gainsboro;
    border-radius: 0 0 10px 10px;
  }

  #container {
    width: 100%;
    background-color: white;
  }

  #results {
    width: 100%;
    /* height: inherit; */
    display: flex;
    flex-direction: column;
    justify-content: flex-start;
    align-items: left;
    background-color: white;
    overflow-y: scroll;
  }

  #checked {
    display: flex;
    flex-direction: column;
    width: 88%;
    justify-content: center;
    align-items: center;
    margin: 0.6rem 1rem;
    background-color:rgb(220, 220, 220, 0.2);
    border-radius: 10px;
    cursor: pointer;
  }

  #unchecked {
    display: flex;
    flex-direction: column;
    width: 88%;
    justify-content: center;
    align-items: center;
    margin: 0.6rem 1rem;
    background-color:rgb(94, 57, 179, 0.1);
    border-radius: 10px;
    cursor: pointer;
  }

  h3 {
    font-size: 1.25rem;
    font-weight: bold;
    margin: 0;
  }

  p {
    font-size: 1.5rem;
    font-weight: bold;
    margin: 0;
  }

  button {
  background-color: rgb(94, 57, 179);
  color: white;
  border-radius: 30px;
  width: 3rem;
  height: 2rem;
  margin: auto 0.5rem auto auto;
  border: none;

  }

  #title {
    width: 100%;
    display: flex;
    justify-content: center;
  }

  #no_result {
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    padding-top: 0;
  }

  #nothing {
    width: 4vh;
    height: 4vh;
    margin-bottom: 2vh;
  }

  #type_follow {
    width: 100%;
    display: flex;
    align-items: center;
  }

  #type_comment {
    width: 100%;
    display: flex;
  }

  #type_feedlike {
    width: 100%;
    display: flex;
  }

  #type_picklike {
    width: 100%;
    display: flex;
  }

  #user {
    width: 3.5vh;
    height: 3.5vh;
    border-radius: 50%;
    margin-left: 0.3rem;
  }

  #search {
    margin-left: 0.5rem;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: flex-start;
  }

  #other-side {
    width: 100vw;
    height: 100vh;
    position: fixed;
    top: 0;
    left: 0;
    z-index: -1;
  }
</style>