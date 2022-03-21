<template>
	<div id="signup_fail">
    <div id="modal">
			<h4>입력 정보를 확인해주세요</h4>
			<hr>
			<p @click="signupAgain">확인</p>
    </div>
	</div>
</template>

<script>
export default {
	methods: {
		signupAgain: function () {
			// console.log('여기옴')
			// console.log(this.$store.state.userInfo)
			this.$store.commit('signupFailModalActivate2')
			this.$router.go(0)
		}
	},
}
</script>

<style scoped>
#signup_fail {
	display: flex;
	justify-content: center;
	align-items: center;
	width: 100%;
	height: 100%;
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
	width: 18rem;
	height: 11rem;
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
	font-weight: bold;
}
</style>