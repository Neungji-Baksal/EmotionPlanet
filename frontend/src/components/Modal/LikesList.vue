<template>
	<div id="likes_list">
		<div id="modal">
		<div id="likes_list_header">
				<div id="title_container">
					<p id="title">좋아요 </p>
				</div>
				<div id="cancel">
					<i @click="goBack" class="fa-solid fa-x" style="font-size: 1.3rem; cursor: pointer;"></i>
				</div>
			</div>
			<hr>
			<div id="no_result" v-if="feedLikesList.length === 0">
				<img id="nothing" src="@/assets/images/etc/alien.png" alt="no result">
				<p id="no_likes">좋아요 목록이 없습니다...</p>
			</div>
			<div id="feed_likes_list" v-else>
				<div v-for="(liker, index) in feedLikesList" :key="index">
					<div id="userInfo">
						<img id="profile_img" :src="liker.profileImg" alt="">
						<p id="username">{{liker.nickname}}</p>
						<!-- <button id="follow_cancel">취소</button> -->
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
			feedLikesList: [],//좋아요 누른 사람 목록
			// userFollowingList:[],//내가 팔로워한 리스트
		}
	},
	methods: {
		goBack: function () {
			// console.log('여기옴')
			// console.log(this.$store.state.userInfo)
			this.$store.commit('likesListActive')
		}
	},
	created () {
		this.feedLikesList = this.$store.state.feedLikesInfo
		// this.userFollowingList=this.$store.state.userFollowing
		// console.log(this.userFollowingList)
	}
}
</script>

<style scoped>
#likes_list {
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
	width: 25vw;
	min-width: 350px;
	height: 45vh;
	min-height: 450px;
}
#likes_list_header {
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
#no_likes {
	font-weight: bold;
}
#feed_likes_list{
	margin-left: 1rem;
	overflow-y: scroll;
	height: 82%;
}
#userInfo{
	display: flex;
	flex-direction: row;
	margin-bottom:1rem;
	margin-top: 1rem;
}

#profile_img {
	width: 2rem;
	height: 2rem;
	border-radius: 50%;
	margin-right: 0.5rem;
	margin-top: auto;
	margin-bottom: auto;
}
#username {
	font-weight: bold;
	margin-right: 0.5rem;
	margin-top: auto;
	margin-bottom: auto;
}
#following_check{
	color: blue;
	font-size: 0.8rem;
	margin-top: auto;
	margin-bottom: auto;
}
#follow_cancel{
	margin-right: 0.5rem;
	margin-left: auto;
	margin-top: auto;
	margin-bottom: auto;
	background-color: #5E39B3;
	color: white;
	border-radius: 10px;
	font-size: 0.8rem;
	padding: 0.1rem;
}
hr {
	margin: 0;
}
</style>