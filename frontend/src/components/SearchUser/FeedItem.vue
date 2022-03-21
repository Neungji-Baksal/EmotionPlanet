<template>
  <article class="feed">
    <img class="feed-img" :src="feed.postImage" alt="feed image">
    <img class="feed-planet" :src="require(`@/assets/images/emotions/${img}`)">
  </article>
</template>

<script>
export default {
	data(){
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
		}
	},
  props: {
    feed: Object
  },
	computed: {
		img(){
			return this.planetStyles[this.feed.planet].img
		}
	}
}
</script>

<style scoped>
  .feed {
		position: relative;
		width: 100%;
		aspect-ratio: 1/1;
	}

	.feed-img {
		border-radius: 10px;
		width: 100%;
		height: 100%;
	}

	.feed-planet {
		position: absolute;
		width: 25%;
		height: 25%;
		bottom: 5%;
    left: 5%;
		border-radius: 50%;
		border: 3px solid;
		border-color: white;
	}
</style>