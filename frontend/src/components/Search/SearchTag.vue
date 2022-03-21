<template>
  <div id="container">
    <div id="results" v-if="this.$store.state.tagSearch.length !== 0">
      <div v-for="result in this.$store.state.tagSearch"
        :key="result.no"
        id="result">
        <img src="../../assets/images/icons/hashtag.png" alt="" id="hashtag">
        <div id="search">
          <span id="title">#{{ result.name }}</span>
          <span id="content">이야기: {{ result.count }}개</span>
        </div>
        <img src="../../assets/images/icons/search_dark.png" alt="" id="go" @click="searchTag(result.name)">
      </div>
    </div>
    <div v-else id="no_result">
      <img id="nothing" src="@/assets/images/etc/alien.png" alt="">
      <h3>찾는 이야기가 없어요...</h3>
    </div>
  </div>
</template>

<script>
export default {
  name: 'SearchTag',
  methods: {
    async searchTag(el) {
      this.$store.state.tagSearchResult = []
      await this.$store.dispatch('searchTagSearch', el)
      this.$router.push({ path: `/search` })
      this.$store.state.searching = false
    }
  },
  created() {
    console.log(this.$store.state.words)
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
  }

  #title {
    font-size: 1.2rem;
    font-weight: bold;
  }

  #hashtag {
    width: 4vh;
    height: 4vh;
    border-radius: 30%;
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
</style>