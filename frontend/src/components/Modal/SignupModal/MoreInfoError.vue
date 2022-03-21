<template>
	<div id="signup_fail">
    <div id="modal">
			<h4> {{serverErrorMessage}}</h4>
			<hr>
			<p @click="signupAgain">확인</p>
    </div>
	</div>
</template>

<script>
import { mapState } from 'vuex'

export default {
	methods: {
		signupAgain: function () {
			// console.log('여기옴')
			// console.log(this.$store.state.userInfo)
			this.$store.commit('signupFailModalActivate1')
			this.$router.go(0)
		}
	},
	computed: 
		mapState([
			'serverErrorMessage'
		])
}
</script>

<style scoped>
#signup_fail {
	display: flex;
	justify-content: center;
	align-items: center;
	width: 100vw;
	height: 100vh;
	background-color: rgb(0, 0, 0, 0.5);
	position: fixed;
	top: 0;
	left: 0;
	z-index: 9999;
}
#modal {
	display: flex;
	flex-direction: column;
	justify-content: center;
	background-color: white;
	border-radius: 20px;
	width: 20vw;
	height: 15vh;
}
p {
	margin: auto;
	font-weight: bold;
	cursor: pointer;
}
hr {
	margin: 0;
}
h4 {
	margin: auto;
	text-align: center;
}
</style>