<template>
	<div id="emotiontest_pick_more">
    <div id="modal">
			<h4>
				{{planetName}}
				<img id="planet_img" :src="require('@/assets/images/emotions/' + planetImg)" alt="">
				으로 향해볼까요?
			</h4>
			<hr>
			<p @click="goMain">확인</p>
    </div>
	</div>
</template>

<script>
export default {
	data() {
		return {
			planetStyles: [
        { id: 1, name: '행복행성', img: "happy.png", color: '#6BD9E8' },
        { id: 2, name: '우울행성', img: "depressed.png", color: '#2A61F0' },
        { id: 3, name: '떠돌이행성', img: "space-station.png", color: '#ABBECA' },
        { id: 4, name: '공포행성', img: "fear.png", color: '#ED5A8E' },
        { id: 5, name: '깜짝행성', img: "surprised.png", color: '#FEA95C' },
        { id: 6, name: '분노행성', img: "rage.png", color: '#FB5D38' },
      ],
			planetName: null,
			planetImg: null,
		}
	},
	methods: {
		goMain: function () {
			// console.log('여기옴')
			console.log(this.$store.state.userInfo)
			this.$store.commit('emotionTestResultModalActivate')
			this.$router.push({name: 'Main'})

		}
	},
	created: function () {
		let mood = this.$store.state.userInfo.mood
		console.log('모달창와서')
		console.log(this.$store.state.userInfo)
		let planetstyle = this.planetStyles.find(el => el.id === mood) || {}
		this.planetImg = planetstyle.img
		this.planetName = planetstyle.name
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
	width: 20rem;
	height: 11rem;
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
#planet_img {
	width: 2rem;
	height: 2rem;
}
</style>