<template>
  <div id="search-result-container">
    <div id="search-taps">
      <h2 @click="changeTab('feed')" :class="{ 'active':tab == 'feed' }">피드</h2>
      <h2 @click="changeTab('pick')" :class="{ 'active':tab == 'pick' }">찜 목록</h2>
    </div>
    <router-view />
  </div>
</template>

<script>

export default {
  data(){
    return {
      tab: 'feed',
      pickTap: 1,
    }
  },
  methods: {
    changeTab(payload){
      this.tab = payload
      this.$router.push({ path: `/search/${this.tab}` })
    }
  },
  watch: {
    test(){
      console.log(this.test)
    }
  },
  mounted(){
    console.log(this.$route.query.tag)
    if (this.$route.path.includes('pick')){
      this.tab = 'pick'
    }
  }
}
</script>



<style scoped>
  h2 {
    color: #777777;
    font-size: 1.5rem;
    margin: 0 1rem;
    cursor: pointer;
  }

  #search-result-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    width: 50%;
    min-width: 700px;
    min-height: 100vh;
    border: 2px #cccccc solid;
    margin: 0 auto;
  }

  #search-taps {
    display: flex;
    justify-content: center;
    align-items: center;
    width: 100%;
    padding: 1rem;
    border-bottom: 1px #cccccc solid;
  }

  #pick-container {
    display: flex;
		flex-direction: column;
		align-items: center;
		width: 100%;
    margin-top: 3rem;
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
		padding-top: 20vh;
	}

	#nothing {
    width: 10%;
    height: inherit;
    aspect-ratio: 1/1;
  }


  .active {
    color: #5e39b3;
    font-size: 1.75rem;
    font-weight: bold;
  }

</style>