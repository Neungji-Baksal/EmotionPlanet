<template>
	<div id="user_feed_setting_modal">
		<div id="modal">
			<p @click="feedUpdateActivate">수정</p>
			<hr>
			<p style="color: red;" @click="feedDelete">삭제</p>
			<hr>
			<p @click="cancel">취소</p>
		</div>
	</div>
</template>

<script>
import axios from 'axios'
import {mapState} from 'vuex'

const session = window.sessionStorage; 
export default {
	data: function () {
		return {
			feedNum: null,

		}
	},
	methods: {
		cancel: function () {
			this.$store.commit('userFeedSettingModalActivate')
		},
		feedUpdateActivate: function () {
			this.$store.commit('userFeedSettingModalActivate')
			this.$store.commit('feedUpdateActivate')
		},
		feedDelete: function () {
			let headers = {
				'at-jwt-access-token': session.getItem('at-jwt-access-token'),
				'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
			};

			axios({
				method: 'delete',
				url: '/api/feeds/' + this.feedNum,
				headers: headers,  // 넣는거 까먹지 마세요
				}).then((res) => {

				this.$store.dispatch('accessTokenRefresh', res) // store아닌곳에서
				this.$router.push({ path: `/user/${this.feedAuthor}`})

				}).catch((error) => {
					console.log(error);
				}).then(() => {
					console.log('getQSSList End!!');
				})
			this.$store.commit('userFeedSettingModalActivate')
		}
	},
	computed: {
		...mapState([
			'feedDetailNum', 'feedAuthor'
		])
	},
	created () {
		this.feedNum = this.feedDetailNum
		console.log(typeof(this.feedNum))
	}
}
</script>

<style scoped>
#user_feed_setting_modal {
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
	display: flex;
	flex-direction: column;
	background-color: white;
	border-radius: 20px;
	width: 16rem;
	height: 13rem;
	text-align: center;
}
hr {
	margin: 0rem;
}
p {
	margin: auto;
	font-weight: bold;
	cursor: pointer;
	font-size: 1.2rem;
}
</style>