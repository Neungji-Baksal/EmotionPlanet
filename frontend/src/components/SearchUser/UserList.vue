<template>
  <article id="list-container">
		<filter-tab :user-mood="userMood" @filtering="filtering" />

		<div id="feed-container" v-if="tab == 'feed'"> 
			<feed-list :feeds="filteredFeeds"/>
		</div>

		<div id="pick-container" v-if="tab == 'pick'">
			<div id="pick-tab">
				<h3 @click="pickTap = 1" :class="pickTap == 1 ? 'active': ''">음악</h3>
				<h3 @click="pickTap = 2" :class="pickTap == 2 ? 'active': ''">영화</h3>
				<h3 @click="pickTap = 3" :class="pickTap == 3 ? 'active': ''">활동</h3>
			</div>
			<div id="picks"> 
				<pick-list v-for="(pick, idx) in filteredPicks" :key="idx" :pick="pick" />
			</div>
		</div>

		<div id="no-result" 
		v-if="(tab == 'feed' && !filteredFeeds.length)||(tab == 'pick' && !filteredPicks.length)">
			<img id="nothing" src="@/assets/images/etc/alien.png" alt="no result">
			<p v-if="tab == 'feed' && !filteredFeeds.length">게시글이 없어요...</p>
			<p v-if="tab == 'pick' && !filteredPicks.length">찜목록이 없어요...</p>
		</div>
		
	</article>
</template>

<script>
import FilterTab from '@/components/SearchUser/FilterTab'
// import FeedItem from '@/components/user/FeedItem'
import FeedList from '@/components/SearchUser/FeedList'
import PickList from '@/components/SearchUser/PickList'

export default {
	name: 'UserFeed',
	data: function () {
		return {
			planetStyles: [
				{ id: 0, name: 'default'},
        { id: 1, name: '행복행성', img: "happy.png", color: '#ED5A8E' },
        { id: 2, name: '우울행성', img: "depressed.png", color: '#6BD9E8' },
        { id: 3, name: '떠돌이행성', img: "space-station.png", color: '#C5D3DC' },
        { id: 4, name: '공포행성', img: "fear.png", color: '#FEA95C' },
        { id: 5, name: '깜짝행성', img: "suprised.png", color: '#FB5D38' },
        { id: 6, name: '분노행성', img: "rage.png", color: '#2A61F0' },
      ],
			filter: 0,
			pickTap: 1,
			filteredFeed: []
		}
	},
	props: {
		tab: String
	},
	components: {
		FilterTab,
		FeedList,
		PickList
	},
	methods: {
		filtering(payload){
      this.filter = payload
			this.filteredFeed = []
    }
	},
	computed: {
		filteredFeeds(){
			console.log(this.$store.state.searchUserInfo)
			if (this.filter){
				this.$store.state.searchUserFeedInfo.forEach(feed => {
					if (feed.tags[0].no == this.filter){
						this.filteredFeed.push(feed)
					}
				});
				console.log(this.filteredFeed)
				return this.filteredFeed
			}
			return this.$store.state.searchUserFeedInfo
		},
		filteredPicks(){
      const temp = []
      this.pickData.forEach(ele => {
        if (!this.filter && ele.no == this.pickTap){
          temp.push(ele)
        }
        else if (ele.no == this.pickTap && ele.tagNo == this.filter){
          temp.push(ele)
        }
      })
      return temp
    },
		userMood(){
			return this.$store.state.userInfo.mood
		}
	},
	created(){
		console.log(this.$route)
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
    font-size: 1.25rem;
    font-weight: bold;
    margin: 3rem;
  }

	#list-container {
		display: flex;
		flex-direction: column;
		justify-content: flex-start;
		align-items: center;
		width: 100%;
	}

	#feed-container {
		width: 100%;
		/* display: grid;
		grid-template-columns: 1fr 1fr 1fr 1fr;
		grid-auto-flow: row;
		justify-content: center;
		gap: 1rem; */
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
		padding-top: 20vh;
	}

	#nothing {
    width: 10%;
    height: inherit;
    aspect-ratio: 1/1;
  }

	#filter {
		display: flex;
	}

	.active {
    color: black;
    font-size: 1.4rem;
    font-weight: bold;
    margin-bottom: 0.5rem;
  }

</style>