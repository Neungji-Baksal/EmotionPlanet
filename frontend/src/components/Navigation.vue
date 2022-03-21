<template>
  <div id="nav">
    <nav class="navbar navbar-expand-lg" id="navbar-default">
      <div class="container">
        <div>
          <img src="@/assets/images/logo/EMOTION PLANET.png" id="logo_img" alt="logo" @click="navClick">
        </div>
        <form class="d-flex" id="searches">
          <div class="search_menu" v-on:cancel="searchOff">
            <i id="find_icon" class="fa-solid fa-magnifying-glass"></i>
            <input id="search_bar" class="form-control" autocomplete="off"
            type="search" placeholder="Search" aria-label="Search"
            @focus="searchOn" :value="searchWords" @input="search">
            <search v-if="searchRecommend" v-on:cancel="searchOff" id="dropdown"></search>
          </div>
          <!-- <button class="btn btn-outline-success" type="submit" id="search"><img src="@/assets/images/search.png" id="search"></button> -->
          <!-- <img src="@/assets/images/icons/search.png" id="search" type="submit"> -->
        </form>
        <div id="icons">
          <img @click="navClick"  id="write"
          :src="require(`@/assets/images/icons/${feed}`)">
          <img @click="navClick" id="home"
          :src="require(`@/assets/images/icons/${home}`)">
          <img @click="navClick" id="my_page"
          :src="require(`@/assets/images/icons/${myPage}`)">
          <div id="alarm_menu">
            <img @click="alarmClick" id="alarm"
            :src="require(`@/assets/images/icons/${alarm}`)">
            <span id="alarm_box" v-if="this.alarmCount >= 1">
              <span id="count_box">
                <p v-if="this.alarmCount <= 9" id="alarm_count">{{ alarmCount }}</p>
                <!-- <p id="alarm_count">{{ alarmCount }}</p> -->
                <p v-if="this.alarmCount >= 10" id="nine">9</p>
                <p v-if="this.alarmCount >= 10" id="plus">+</p>
              </span>
            </span>
            <alarm v-if="alarming" id="alarm_drop" @cancelAlarm="alarmClose"></alarm>
          </div>
          <img @click="navClick" id="setting"
           :src="require(`@/assets/images/icons/${setting}`)">
           <img src="@/assets/images/icons/power.png" @click="signout" 
           id="logout" style="cursor:pointer;">
        </div>
      </div>
    </nav>
  </div>
</template>
<script>
// import {mapState} from 'vuex'
import Search from '@/components/Search/Search'
import Alarm from '@/components/Alarm'

// const session = window.sessionStorage

export default {
  name: 'App',
  data: function (){
    return {
      //검색입니둥
      searchWords: null,
      //알람입니둥
      alarmwatch: 0,
    }
  },
  components: { Search, Alarm },
  methods: {
    navClick(event){
      // console.log(this.$router)
      if (event.target.id == 'write'){this.$store.commit('navActivate', 0)}
      else if (event.target.id == 'home' || event.target.id =='logo_img'){this.$router.push({ name:'Main' })}
      else if (event.target.id == 'my_page'){this.$router.push({ name:'Mypage' })}
      // else if (event.target.id == 'alarm'){this.$store.commit('navActivate', 3)}
      else {this.$router.push({ name:'Setting' })}
    },
    //검색 부분입니둥
    searchOn() {
      this.$store.state.searching = true
    },
    searchOff() {
      this.$store.state.searching = false
      this.$store.state.words = null
      this.$store.state.tagSearch = []
      this.$store.state.userSearch = []
      this.$store.state.pickSearch = []
    },
    search( searchWords ) {
      this.$store.commit('updateSearch', searchWords.target.value)
      this.$store.dispatch('searchTag')
      this.$store.dispatch('searchUser')
      // this.$store.dispatch('searchPick')
    },
    // 검색 끝
    signout() {
      this.$store.commit('logoutModalActivate')
    },
    alarmClick() {
      this.$store.commit('navActivate', 3)
      this.$store.dispatch('alarmselect')
    },
    alarmClose() {
      this.$store.commit('navActivate', 3)
    },
  },
  computed: {
    feed(){
      if (!this.navActive[0]){return 'more.png'}
      else{return 'more_selected.png'}
    },
    home(){
      if (!this.navActive[1]){return 'home.png'}
      else{return 'home_selected.png'}
    },
    myPage(){
      console.log(!this.navActive[2])
      if (!this.navActive[2]){return 'user.png'}
      return 'user_selected.png'
    },
    alarm(){
      if (!this.navActive[3]){return 'bell.png'}
      return 'bell_selected.png'
    },
    setting(){
      if (!this.navActive[4]){return 'settings.png'}
      return 'settings_selected.png'
    },
    navActive(){
      return this.$store.state.navActive
    },
    alarmCount() {
      let count = 0
      this.$store.state.alarm.forEach(el => {
        if(el.readcheck == 0){
          count++
        }
      });
      console.log(count)
      return count
    },
    searchRecommend(){
      return this.$store.state.searching
    },
    alarming(){
      return this.$store.state.navActive[3]
    }
  },
}
</script>

<style scoped>
#nav {
  text-align: center;
  color: #2c3e50;
  width: 100%;
  min-width: 700px;
}

#nav a {
  font-weight: bold;
  color: #2c3e50;
}

#nav a.router-link-exact-active {
  color: #42b983;
}
#navbar-default{
  background-color: rgb(94, 57, 179);

}
#logo_img{
  width: 70px;
  height: 40px;
}
.container{
  display:flex;
  flex-direction: row;
  justify-content: space-between;
  flex-wrap: nowrap;
  width: 52%;
  min-width: 700px;
}
#search_bar{
  width: 20vw;
  height: 35px;
  margin-top:auto;
  margin-bottom: auto;
  padding-left: 2rem;
}
#search{
  width: 25px;
  height: 25px;
}
#icons {
  display: flex;
  flex-direction: row;
  margin-left: 0px;
}
#setting{
  width: 25px;
  height: 25px;
  margin: 10px;
}
#write{
  width: 25px;
  height: 25px;
  margin: 10px;
}
#home{
  width: 25px;
  height: 25px;
  margin: 10px;
}
#my_page{
  width: 25px;
  height: 25px;
  margin: 10px;
}
#logout{
  width: 33px;
  height: 33px;
  margin: 5px;
}
#alarm_menu{
  /* width: 25px;
  height: 25px;
  margin: 10px; */
  position: relative;
}
#alarm{
  width: 25px;
  height: 25px;
  margin: 10px;
  position: relative;
}
#alarm_box{
  display: flex;
  width: 20px;
  height: 20px;
  border-radius: 50%;
  background-color: red;
  top: 0;
  left: 1.4rem;
  position: absolute;
}
#count_box{
  display: flex;
  align-items: center;
  left: 0.28rem;
  bottom: -1.2rem;
  position: absolute;
}

#alarm_count{
  font-size: 1rem;
  font-weight: bold;
  color: white;
}

#alarm_drop {
  z-index: 20;
  width: 15%;
  min-width: 300px;
  height: 30%;
  min-height: 340px;
  position: absolute;
  background-color: white;
  margin: 0.5rem -7.8rem;
}

#nine{
  font-size: 1rem;
  font-weight: bold;
  color: white;
}

#plus {
  font-size: 1rem;
  font-weight: bold;
  color: white
}
/* .note-num {
  position: absolute;
  top: 0;
  right: 0;
  z-index: 3;
  height: 20px;
  width: 20px;
  line-height: 20px;
  text-align: center;
  background-color: red;
  border-radius: 15px;
  display: inline-block;
  color: white;
} */
#search{
  width: 25px;
  height: 25px;
  margin: 10px;
  position: relative;
} 
img{
  cursor: pointer;
}
#find_icon{
  font-size: 1.2rem;
  position: absolute;
  color: gray;
  top: 20%;
  left: 2%;
}
.search_menu {
  display: flex;
  flex-direction: row;
  position: relative;
}

#dropdown {
  z-index: 20;
  width: 25%;
  min-width: 150px;
  height: 15%;
  position: absolute;
  background-color: white;
  margin-top: 3rem;
}
</style>

<!-- 알림버튼 숫자표시 
#HTML
<div class="nav-right">
        <div class="nav-btn" id="friend"></div>
        <div class="nav-btn" id="notification"><span class="note-num">3</span></div>
        <a id="logout" role="button" href="{% url 'logout' %}">로그아웃</a>
</div>

#CSS
note-num {
    position: absolute;
    top: 0;
    right: 0;
    z-index: 3;
    height: 20px;
    width: 20px;
    line-height: 20px;
    text-align: center;
    background-color: red;
    border-radius: 15px;
    display: inline-block;
}

#notification {
    background-image: url('../images/notification.svg');
    position: relative;
} -->