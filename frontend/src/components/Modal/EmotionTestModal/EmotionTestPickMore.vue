<template>
	<div id="emotiontest_pick_more">
    <div id="modal">
			<h4>조금만 더 골라주세요🤣</h4>
			<hr>
			<p @click="goBack">확인</p>
    </div>
	</div>
</template>

<script>
export default {
	methods: {
		goBack: function () {
			// console.log('여기옴')
			// console.log(this.$store.state.userInfo)
			this.$store.commit('emotionTestPickMoreModalActivate')
		}
	}
}
</script>

<style scoped>
#emotiontest_pick_more {
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
	border-radius: 30px;
	width: 18rem;
	height: 10rem;
}
p {
	margin: auto;
	font-weight: bold;
	cursor: pointer;
	font-size: 1.25rem;
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