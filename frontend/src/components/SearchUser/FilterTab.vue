<template>
  <div id="filter-container">
		<img id="planet_img" :src="require('@/assets/images/emotions/' + planet)">
		<select id="selectbox" v-model="filterValue" @change="filtering">
			<option value="0">전체</option>
			<option value="1">행복행성</option>
			<option value="2">우울행성</option>
			<option value="3">떠돌이행성</option>
			<option value="4">공포행성</option>
			<option value="5">깜짝행성</option>
			<option value="6">분노행성</option>
		</select>
  </div>
</template>

<script>
export default {
	name:'FilterTab',
	data: function () {
		return {
			planetStyles: [
				{ id: 0, name: 'default'},
        { id: 1, name: '행복행성', img: "happy.png", color: '#6BD9E8' },
        { id: 2, name: '우울행성', img: "depressed.png", color: '#2A61F0' },
        { id: 3, name: '떠돌이행성', img: "space-station.png", color: '#ABBECA' },
        { id: 4, name: '공포행성', img: "fear.png", color: '#ED5A8E' },
        { id: 5, name: '깜짝행성', img: "surprised.png", color: '#FEA95C' },
        { id: 6, name: '분노행성', img: "rage.png", color: '#FB5D38' },
      ],
			filterValue: '0',
		}
	},
	props: {
		userMood: Number,
	},
	methods: {
		filtering: function () {
			this.$emit('filtering', Number(this.filterValue))
		}
	},
	computed: {
    planet() {
			const idx = Number(this.filterValue)
			if (idx){
				return this.planetStyles[idx].img
			}
			return "space-station.png"
		}
  },
}
</script>

<style scoped>
	#filter-container {
		display: flex;
		justify-content: flex-end;
		align-items: center;
		align-self: flex-end;
		margin: 2rem;
	}

	#planet_img {
		width: 5%;
		height: inherit;
		aspect-ratio: 1/1;
		margin: 0 1rem;
	}

	select { 
		/* padding: 0.2rem 2rem 0 0; */
		padding-right: 2rem;
		border: none;
		border-radius:0; /* 아이폰 사파리 보더 없애기 */ 
		-webkit-appearance:none; /* 화살표 없애기 for chrome*/ 
		-moz-appearance:none; /* 화살표 없애기 for firefox*/ 
		appearance:none; /* 화살표 없애기 공통*/ 
		background: url('../../assets/images/etc/rocket.png') no-repeat 97% 50%/2.2vh auto;
		font-size: 1.5rem;
		font-weight: bold;
		text-align: center;
		cursor: pointer;
	}

	select:focus {
		outline: none;
	}

	select::-ms-expand {
		display: none;
	}
</style>