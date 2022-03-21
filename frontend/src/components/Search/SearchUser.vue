<template>
  <div id="container">
    <div id="results" v-if="searchUser.length !== 0">
      <div v-for="result in searchUser"
      :key="result.no" class="result" @click="getInfo(result.no)">
        <div id="user_info">
          <img :src="result.profileImg" alt="" id="user">
          <p id="title">@{{ result.nickname }}</p>
        </div>
        <img src="../../assets/images/icons/search_dark.png" alt="" id="go">
      </div>
    </div>
    <div v-else id="no_result">
      <img id="nothing" src="@/assets/images/etc/alien.png" alt="">
      <h3>찾는 여행자가 없어요...</h3>
    </div>  
  </div>
</template>

<script>
export default {
  name: 'SearchUser',
  methods: {
    async getInfo(el) {
      console.log('유저에용',el)
      const to = `/user/${el}`
      console.log(to)
      this.$store.state.searchUserNo = el
      await this.$store.dispatch('userSelect', el)
      await this.$store.dispatch('userfollowdate', el)
      // await this.$store.dispatch("searchUserFeed", this.$store.state.searchUserNo)
      // window.location.reload()

      this.$router.push({ path: to })
    }
  },
  computed: {
    searchUser(){
      return this.$store.state.userSearch
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

  .result {
    display: flex;
    width: 85%;
    align-items: center;
    margin: 1rem 1rem;
    background-color: white;
    border-bottom: 0.1rem gainsboro;
    cursor: pointer;
  }

  #search {
    width: 70%;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: flex-start;
    padding-left: 0.5rem;
    padding-right: 2rem;
  }

  #title {
    font-size: 1.2rem;
    font-weight: bold;
    margin-top: auto;
    margin-bottom: auto;
    margin-right: 0.4rem;
  }

  #go {
    width: 1.5rem;
    height: 1.5rem;
    margin-left: auto;
    cursor: pointer;
  }
  #user_info {
    display: flex;
    flex-direction: row;
    cursor: pointer;
  }
  #user {
    width: 2.3rem;
    height: 2.3rem;
    border-radius: 50%;
    margin-right: 0.4rem;
  }
  #title {
    font-size: 1.2rem;
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