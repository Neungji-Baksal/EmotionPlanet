<template>
	<div id="comment_setting_modal">
		<div id="modal">
			<p style="color: red;" @click="deleteComment">삭제</p>
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
	methods: {
		data: function () {
			return {
				commentNumber: null,

			}
		},
		cancel: function () {
			this.$store.commit('commentSettingModalActivate')
		},
		deleteComment: function () {
			let headers = {
        'at-jwt-access-token': session.getItem('at-jwt-access-token'),
        'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
			};
			axios({
					method: 'delete',
					url: `/api/comments/${this.commentNumber}`,
					headers: headers,  // 넣는거 까먹지 마세요
				}).then((res) => {

				this.$store.dispatch('accessTokenRefresh', res) // store아닌곳에서
				// this.dispatch('accessTokenRefresh', res) // store에서
				this.$store.commit('isDelete')

				}).catch((error) => {
					console.log(error);
				}).finally(() => {
					console.log('getQSSList End!!');
					this.$store.commit('commentSettingModalActivate')
				});
    },
	},
	computed: {
		...mapState([
			'commentNum'
		])
	},
	created () {
		this.commentNumber = this.commentNum
		console.log(this.commentNumber)
	}
}
</script>

<style scoped>
#comment_setting_modal {
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
	width: 18rem;
	height: 11rem;
	text-align: center;
}
hr {
	margin: 0rem;
}
p {
	margin: auto;
	font-weight: bold;
	cursor: pointer;
	font-size: 1.4rem;
}
</style>