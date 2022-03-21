<template>
  <div id="feed-list">
    <div v-if="showOption == 'grid'" id="grid-container">
      <feed-small v-for="feed in filteredFeeds"
        :feed="feed"
        :key="feed.no" />
    </div>
    <div id="no-result" 
			v-if="!filteredFeeds.length">
			<img id="nothing" src="@/assets/images/etc/alien.png" alt="no result">
			<p>게시글이 없어요...</p>
		</div>
  </div>
</template>

<script>
// import Feed from "@/components/user/Feed.vue";
import FeedSmall from "@/components/user/FeedSmall.vue";
import axios from 'axios'

export default {
  name: "FeedList",
  data(){
    return {
      rawFeeds: null,
      showOption: 'grid'
    }
  },
  props: {
    filter: Number,
    userId: Number,
  },
  components: {
    // Feed,
    FeedSmall
  },
  computed: {
    filteredFeeds(){
      const temp = []
      if (this.rawFeeds){
        if (this.filter){
          this.rawFeeds.forEach(ele => {
            if (ele.tags[0].no == this.filter){
              temp.push(ele)
            }
          })
        }
        else {
          return this.rawFeeds
        }
      }
      return temp
    }
  },
  created(){
    const session = window.sessionStorage
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
      url:`/api/feeds/my/${user}`,
      headers:headers,
    })
    .then((res) => {
      if(res.headers['at-jwt-access-token'] != session.getItem('at-jwt-access-token')){
        session.setItem('at-jwt-access-token', "");
        session.setItem('at-jwt-access-token', res.headers['at-jwt-access-token']);
        console.log("Access Token을 교체합니다!!!")
      }
      this.rawFeeds=res.data
      console.log('내는 피드리스트여', this.rawFeeds)
      this.$emit('comp')
    })
    .catch((error) => {
      console.log('FeedList', error);
    })
	}
};
</script>

<style scoped>
  h3 {
    margin: 0 1rem;
  }

  p {
    color: #777777;
    font-size: 1.5rem;
    font-weight: bold;
    margin: 2.5rem;
  }

  button {
    width: 4vh;
    height: 4vh;
    background-size: cover;
    border: none;
    margin: 0.5rem;
    border-radius: 20%;
  }

  #feed-list {
    display: flex;
    flex-direction: column;
    align-items: center;
    width: 100%;
  }

  #show-btns {
    display: flex;
    align-items: center;
    align-self: flex-start;
    box-sizing: content-box;
    margin: 1rem;
  }

  #grid-container {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr 1fr;
    gap: 1rem;
    width: 100%;
    padding: 2rem;
  }

  #card-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    width: 100%;
    padding: 1rem;
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

  .g {
    background-image: url('../../assets/images/icons/grid.png');
  }

  .g-active {
    background-image: url('../../assets/images/icons/grid-active.png');
  }

  .c {
    background-image: url('../../assets/images/icons/card.png');
  }

  .c-active {
    background-image: url('../../assets/images/icons/card-active.png');
  }
</style>