<template>
  <article id="list-container">
		<filter-tab :user-mood="userMood" @filtering="filtering" />
		<feed-list :filter="filter" :userId="userId" @comp="prepared = 'feed'" v-if="tab == 'feed'"/>
		<pick-list :filter="filter" :userId="userId" @comp="prepared = 'pick'" v-if="tab == 'pick'" />
	</article>
</template>

<script>
import FilterTab from '@/components/user/FilterTab'
import FeedList from '@/components/user/FeedList'
import PickList from '@/components/user/PickList'

export default {
	name: 'List',
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
			pickTab: 1,
			prepared: null
		}
	},
	props: {
		tab: String,
		userId: Number,
	},
	components: {
		FilterTab,
		FeedList,
		PickList
	},
	methods: {
		filtering(payload){
      this.filter = payload
    }
	},
	computed: {
		userMood(){
			return this.$store.state.userInfo.mood
		},
	},
	watch: {
		prepared(){
			console.log('나 여기있어요!!!!!!!!!!!!!!', this.$route.path)
			if (this.$route.path.includes(this.prepared)){
				this.$store.commit('load', false)
			}
		}
	},
	created(){
		if (!this.userId || this.userId == JSON.parse(window.sessionStorage.getItem('userInfo')).no){
			document.title = `마이페이지 - ${this.tab}`
		}
		else {
			document.title = `유저페이지 - ${this.tab}`
		}
	}
}
</script>

<style scoped>  
	#list-container {
		display: flex;
		flex-direction: column;
		justify-content: flex-start;
		align-items: center;
		width: 100%;
	}

	#filter {
		display: flex;
	}
</style>