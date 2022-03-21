<template>
	<div id="moreinfo_confirm_modal">
    <div id="modal">
			<h4>갱신이 완료되었습니다.</h4>
			<hr>
			<p @click="goLogin">확인</p>
    </div>
	</div>
</template>

<script>
export default {
	methods: {
		goLogin: function () {
		// console.log(this.$store.state.userInfo)
		this.$store.commit('moreInfoConfirmModalActivate')
		this.$router.push({name: 'EmotionTest'})
		}
	}
}
</script>

<style scoped>
#moreinfo_confirm_modal {
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