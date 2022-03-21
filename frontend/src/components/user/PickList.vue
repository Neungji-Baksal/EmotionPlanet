<template>
  <div id="pick-container">
    <div id="pick-tab">
      <h3 @click="pickTab = 0" :class="pickTab == 0 ? 'active': ''">음악</h3>
      <h3 @click="pickTab = 1" :class="pickTab == 1 ? 'active': ''">영화</h3>
      <h3 @click="pickTab = 2" :class="pickTab == 2 ? 'active': ''">활동</h3>
    </div>
    <div id="picks"> 
      <pick-item v-for="(pick, idx) in filteredPicks" :key="idx" :pick="pick" />
    </div>
    <div id="no-result" 
      v-if="!filteredPicks.length">
      <img id="nothing" src="@/assets/images/etc/alien.png" alt="no result">
      <p>찜목록이 없어요...</p>
    </div>
  </div>
</template>

<script>
import PickItem from '@/components/user/PickItem'
import axios from 'axios'

const session = window.sessionStorage;

export default {
  data(){
    return {
      rawPicks: null,
      pickTab: 0
    }
  },
  props: {
    filter: Number,
    userId: String
  },
  components: {
    PickItem
  },
  computed:{
    filteredPicks(){
			const temp = []
			if (this.rawPicks){
        this.rawPicks.forEach(ele => {
          if (this.filter){
            if (this.filter == ele.tagNo && this.pickTab == ele.type){
              temp.push(ele)
            }
          }
          else if (this.pickTab == ele.type){
            temp.push(ele)
          }
        })
			}
      return temp
		}
  },
  created(){
    let user = JSON.parse(session.getItem('userInfo')).no

    if (this.userId){
      user = this.userId
    }

    let headers = {
      'at-jwt-access-token': session.getItem('at-jwt-access-token'),
      'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
    };
    axios({
      method:'get',
      url:`/api/picks/user/${user}`,
      headers:headers,
    })
    .then((res) => {
      if(res.headers['at-jwt-access-token'] != session.getItem('at-jwt-access-token')){
        session.setItem('at-jwt-access-token', "");
        session.setItem('at-jwt-access-token', res.headers['at-jwt-access-token']);
        console.log("Access Token을 교체합니다!!!")
      }
      this.rawPicks = res.data
      this.$emit('comp')
      console.log('성공!! ㅋㅋㅋㅋㅋㅋ', res)
    })
    .catch((error) => {
      console.log(error);
      console.log('찜목록 실패ㅔ..')
    })
  }
}
</script>

<style scoped>
  h3 {
    color: #777777;
    font-size: 1.2rem;
    font-weight: bold;
    margin-bottom: 0.5rem;
    cursor: pointer;
  }

  p {
    color: #777777;
    font-size: 1.5rem;
    font-weight: bold;
    margin: 2.5rem;
  }

  .active {
    color: black;
    font-size: 1.4rem;
    font-weight: bold;
    margin-bottom: 0.5rem;
  }

  #pick-container {
    display: flex;
		flex-direction: column;
		align-items: center;
		width: 100%;
  }

  #pick-tab {
    display: flex;
    width: 40%;
    justify-content: space-evenly;
    align-items: center;
  }

  #picks {
    display: grid;
    justify-content: center;
    justify-items: start;
    align-items: baseline;
    grid-auto-rows: minmax(min-content, max-content);
    grid-template-columns: 1fr 1fr 1fr;
    width: 80%;
    gap: 2rem;
    margin: 5rem;
  }
  
	#no-result {
		display:flex;
		flex-direction: column;
		justify-content: center;
		align-items: center;
		padding-top: 1rem;
	}

	#nothing {
    width: 10%;
		height: 10%;
    height: inherit;
    aspect-ratio: 1/1;
  }
</style>