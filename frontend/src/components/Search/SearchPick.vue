<template>
  <div id="container">
    <div id="results" v-if="this.searchPick !== null">
      <div v-for="(result, idx) in this.searchPick"
        :key="idx"
        id="result">
        <img src="../../assets/images/icons/treasure-chest.png" alt="" id="treasure">
        <div id="search">
          <span class="info">
            <span id="title">#{{ result.name }}행성</span>
            <img class="feed-planet" :src="require('@/assets/images/emotions/' + planetStyles[idx].img)" id="planet">
          </span>
          <span id="content">찜목록: {{ result.count }}개</span>
        </div>
        <img src="../../assets/images/icons/search_dark.png" alt="" id="go" @click="searchPickDetail(result.name)">
      </div>
    </div>
    <div v-else id="no_result">
      <img id="nothing" src="@/assets/images/etc/alien.png" alt="">
      <p>찾는 찜목록이 없어요...</p>
    </div>
  </div>
</template>

<script>
import axios from 'axios'

const session = window.sessionStorage

export default {
  name: 'SearchPick',
  data() {
    return {
      searchPick: null,
      searchPickResult: null,
      planetStyles: [
        { id: 1, name: '행복행성', img: "happy.png", color: '#6BD9E8' },
        { id: 2, name: '우울행성', img: "depressed.png", color: '#2A61F0' },
        { id: 3, name: '떠돌이행성', img: "space-station.png", color: '#ABBECA' },
        { id: 4, name: '공포행성', img: "fear.png", color: '#ED5A8E' },
        { id: 5, name: '깜짝행성', img: "surprised.png", color: '#FEA95C' },
        { id: 6, name: '분노행성', img: "rage.png", color: '#FB5D38' },
      ],
    }
  },
  methods: {
    // 글자가 포함된 태그 찜목록과 태그별 찜목록 개수를 가져옴
    searchPickDetail(el){
      let headers = {
        'at-jwt-access-token': session.getItem('at-jwt-access-token'),
        'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
      };
      axios({
        method: 'get',
        url:'/api/searchs/byPickTag/' + el,
        headers: headers,
      }).then(res => {
        this.$store.dispatch('accessTokenRefresh', res)
        console.log('찜목록 있음', res)
        this.pickSearchResult = res.data
        this.$store.state.tagSearchResult = []
        // this.$bus.$emit('pickBus', this.pickSearchResult)
        this.$store.state.searchPickList = res.data;
        this.$router.push({ path: `/search/pick`, query: { tag: el } })
        this.$store.state.searching = false
      })
      .catch(()=> {
        console.log('찜목록 없음')
        this.pickSearchResult = []
      })
    },
  },
  created() {
    console.log(this.$store.state.words)
    // 클릭하는 태그의 찜목록 정보 전체를 가져옴
    let headers = {
      'at-jwt-access-token': session.getItem('at-jwt-access-token'),
      'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
    };
    axios({
      method: 'get',
      url:'/api/searchs/byPickTagList',
      headers: headers,
    }).then(res => {
      this.$store.dispatch('accessTokenRefresh', res)
      console.log('찜목록 검색 성공', res.data)
      this.searchPick = res.data
      console.log(this.searchPick)
    })
    .catch((err)=> {
      console.log('찜목록 검색 실패')
      console.log(err)
    })
  }
}
</script>

<style scoped>
  h3 {
    font-size: 1.25rem;
    font-weight: bold;
    margin: 0;
  }
  #container {
    width: 100%;
    background-color: white;
  }

  #results {
    width: 100%;
    height: 100%;
    display: flex;
    flex-direction: column;
    align-items: left;
    background-color: white;
    overflow-y: scroll;
  }

  #result {
    display: flex;
    width: 85%;
    align-items: center;
    padding-left: 1rem;
    margin: 1rem 1rem;
    background-color: white;
    border-bottom: 0.1rem gainsboro;
  }

  #search {
    width: 70%;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: flex-start;
    padding-left: 1rem;
    padding-right: 2rem;
    position: relative;
  }

  #title {
    font-size: 1.2rem;
    font-weight: bold;
  }

  #treasure {
    width: 4vh;
    height: 4vh;
    border-radius: 40%;
  }
  
  #go {
    width: 3vh;
    height: 3vh;
    cursor: pointer;
  }

  #no_result {
    display: flex;
    flex-direction: column;
    align-items: center;
    padding-top: 20%;
    
  }

  #nothing {
    width: 5rem;
    height: 5rem;
    margin-bottom: 1rem;
  }

  .info {
    /* width: 100%; */
    /* aspect-ratio: 1/1; */
    /* border-radius: 20px; */
    position: relative;
  }

  .feed-planet {
		position: absolute;
		width: 1.7rem;
		height: 1.7rem;
		bottom: -95%;
    left: -35%;
		border-radius: 50%;
		border: 3px solid;
		border-color: white;
	}
</style>
