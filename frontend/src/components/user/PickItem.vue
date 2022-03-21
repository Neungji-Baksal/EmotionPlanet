<template>
  <article v-if="pick.contentsListData.length" class="picks" style="cursor:pointer" @click="go_to_detail" @mouseover="isHover = true">
    <img :class="{planet, 'movie-planet':pick.no == 2}" :src="require(`@/assets/images/emotions/${planet}`)" alt="">
    <img :class="['thumbnail', {'movie-thumb':pick.no == 2}]" :src="thumbNail" alt="thumbnail">
    <h3>{{ title }}</h3>
    <span v-show="isHover" @mouseleave="isHover = false" class="picks-info">
      <p>Go to Detail</p>
    </span>
  </article>
  <article v-else class="picks" @mouseover="isHover = true">
    <img :class="{planet, 'movie-planet':pick.no == 2}" :src="require(`@/assets/images/emotions/${planet}`)" alt="">
    <img :class="['thumbnail', {'movie-thumb':pick.no == 2}]" :src="thumbNail" alt="thumbnail">
    <h3>{{ title }}</h3>
    <span v-show="isHover" @mouseleave="isHover = false" class="picks-info">
      <p>Empty List</p>
    </span>
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
      isHover: false
    }
  },
  props: {
    pick: Object
  },
  methods: {
    go_to_detail(){
      this.$router.push({path:`/user/${this.pick.userNo}/item/${this.pick.no}`})
    }
  },
  computed: {
    thumbNail(){
      if(this.pick.contentsListData.length>0){
        return this.pick.contentsListData[0].imgLink
      }
      else{
        return this.pick.imgLink
      }
    },
    title(){
      return this.pick.name
    },
    planet(){
      return this.planetStyles[this.pick.tagNo].img
    }
  }
}
</script>

<style scoped>
  h3 {
    font-size: 1.125rem;
    font-weight: bold;
    margin: 0.5rem 0;
    word-break: keep-all;
  }

  p {
    margin: 0;
    font-size: 1.5rem;
    color: rgb(255, 255, 255, 0.75);
  }

  img {
    width: 100%;
    height: inherit;
    aspect-ratio: 1/1;
  }

  .picks {
    display: flex;
    flex-direction: column;
    align-items: center;
    border: none;
    /* cursor: pointer; */
    position: relative;
  }

  .thumbnail {
    border: 1px #cccccc solid;
  }

  .movie-thumb {
    aspect-ratio: 2/3;
  }

  .planet {
    width: 20%;
    border: 3px white solid;
    border-radius: 50%;
    position: absolute;
    left: 5%;
    bottom: 25%;
  }

  .movie-planet {
    bottom: 20%;
  }

  .picks-info {
    display: flex;
    justify-content: center;
    align-items: center;
    position: absolute;
    width: 100%;
    height: 100%;
    top: 0;
    left: 0;
    background-color: rgb(0, 0, 0, 0.5);
    z-index: 1;
  }
</style>