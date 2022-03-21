<template>
	<div id="follower_list">
		<div id="modal">
		<div id="follower_list_header">
				<div id="title_container">
					<p id="title">팔로워 </p>
				</div>
				<div id="cancel">
					<i @click="goBack" class="fa-solid fa-x" style="font-size: 1.3rem; cursor: pointer;"></i>
				</div>
			</div>
			<hr>
			<div id="no_result" v-if="myFollowerInfo.length === 0">
				<img id="nothing" src="@/assets/images/etc/alien.png" alt="no result">
				<p id="no_follower">팔로워 목록이 없습니다...</p>
			</div>
			<div id="my_follower_list" v-else>
				<div v-for="followerInfo in myFollowerInfo" :key="followerInfo.no">
					<div id="userInfo">
						<img id="profile_img" :src="followerInfo.profileImg" alt="" @click="moveToUserPage(followerInfo.no)">
						<p id="username" @click="moveToUserPage(followerInfo.no)">{{followerInfo.nickname}}</p>
					</div>
				</div>
			</div>
		</div>
	</div>
</template>

<script>
export default {
	data () {
		return {
			myFollowerInfo: []
		}
	},
	methods: {
		goBack: function () {
			// console.log('여기옴')
			// console.log(this.$store.state.userInfo)
			this.$store.commit('userpagefollowerListActivate')
		},
		moveToUserPage (el) {
			this.$store.state.searchUserNo = el
			this.$store.dispatch('userSelect', el)
			this.$store.dispatch('userfollowdate', el)
			this.$store.commit('userpagefollowerListActivate')
			this.$router.push({ path: `/userpage/feed` })
		}
	},
	created () {
		this.myFollowerInfo = this.$store.state.searchUserFollowInfo.userFollow
	}
}
</script>

<style scoped>
#follower_list {
	display: flex;
	justify-content: center;
	align-items: center;
	width: 100%;
	height: 100%;
	background-color: rgb(0, 0, 0, 0.5);
	position: fixed;
	top: 0;
	left: 0;
	z-index: 999;
}
#modal {
	background-color: white;
	border-radius: 20px;
	width: 20rem;
	min-width: 350px;
	height: 25rem;
	min-height: 450px;
}
#follower_list_header {
	display: flex;
	flex-direction: row;
	justify-content: center;
	padding-top:1rem;
	padding-bottom: 1rem;
}
#title {
	margin-top: auto;
	margin-bottom: auto;
	font-size: 1.2rem;
	font-weight: bold;
}
#title_container{
	width: 58%;
	display: flex;
	justify-content: right;
}
#cancel {
	width: 42%;
	display: flex;
	justify-content: right;
	margin-right: 1rem;
	margin-top: 0.3rem;
}
#no_result {
	display:flex;
	flex-direction: column;
	align-items: center;
	margin-top: 25%
}
#nothing {
	width: 5rem;
	height: 5rem;
	margin-bottom: 0.5rem;
}
#no_follower {
	font-weight: bold;
}
#my_follower_list{
	margin-left: 1rem;
	overflow-y: scroll;
	height: 40vh;
}
#userInfo{
	display: flex;
	flex-direction: row;
	margin-bottom:1rem;
	margin-top: 1rem;
}

#profile_img {
	width: 3rem;
	height: 3rem;
	border-radius: 50%;
	margin-right: 0.5rem;
	margin-top: auto;
	margin-bottom: auto;
	cursor: pointer;
}
#username {
	font-weight: bold;
	margin-right: 0.5rem;
	margin-top: auto;
	margin-bottom: auto;
	cursor: pointer;
	font-size: 1.3rem;
}
hr {
	margin: 0;
}
</style>