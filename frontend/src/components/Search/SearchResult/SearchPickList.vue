<template>
  <div id="picklist-container">
    <div id="pick-tab">
      <h3 @click="pickTab = 0" :class="pickTab == 0 ? 'active': ''">음악</h3>
      <h3 @click="pickTab = 1" :class="pickTab == 1 ? 'active': ''">영화</h3>
      <h3 @click="pickTab = 2" :class="pickTab == 2 ? 'active': ''">활동</h3>
    </div>
    <div id="picks"> 
      <search-pick v-for="(pick, idx) in filteredPicks" :key="idx" :pick="pick" />
    </div>
  </div>
</template>

<script>
import SearchPick from './SearchPick.vue'

export default {
  data(){
    return {
      pickTab: 1
    }
  },
  components: {
    SearchPick
  },
  props: {
    picks: Array
  },
  computed: {
    filteredPicks(){
      const temp = []
      this.picks.forEach(ele => {
        if (ele.type == this.pickTab){
          temp.push(ele)
        }
      })
      return temp
    }
  }
}
</script>

<style scoped>
  h3 {
    color: #777777;
    font-size: 1.25rem;
    font-weight: bold;
    margin: 0;
    cursor: pointer;
  }


  #picklist-container {
    display: flex;
		flex-direction: column;
		align-items: center;
		width: 100%;
  }

  #pick-tab {
    display: flex;
    width: 40%;
    justify-content: space-evenly;
    align-items: center;
  }

  #picks {
    display: grid;
    justify-content: center;
    justify-items: start;
    align-items: baseline;
    grid-auto-rows: minmax(min-content, max-content);
    grid-template-columns: 1fr 1fr 1fr;
    width: 80%;
    gap: 2rem;
    margin: 5rem;
  }

	.active {
    color: black;
    font-size: 1.4rem;
    font-weight: bold;
    margin-bottom: 0.5rem;
  }
</style>