<template>
  <div id="pick-item-container">
    <div id="pick-item-header">
      <img :class="{'movie-poster':index==2}" :src="selectedItem.postImgLink" :alt="selectedItem.name">
      <table>
        <tr @click="selected = idx" v-for="(item, idx) of pickItem" :key="item.name" :class="{ 'selected':selected == idx }">
          {{ item.name }} - {{ item.author }}
        </tr>
      </table>
    </div>
    <div id="pick-item-body">
      <span class="pick-item-info" v-for="key of ['name', 'author', 'year', 'postImgLink']" :key="key">
        <h5>{{ key }}</h5>
        <p>{{ selectedItem[key] }}</p>
      </span>
    </div>
  </div>
</template>

<script>
import pickData from '../../assets/data/pickData'

export default {
  data(){
    return {
      pickData,
      selected: 0,
    }
  },
  props: {
    id: String,
    tag: String,
    index: String
  },
  computed: {
    pickItem(){
      const temp = this.pickData.filter(ele => 
       (ele.userNo == Number(this.id) && ele.tagNo == Number(this.tag) && ele.no == Number(this. index))
      )
      return temp[0].contentsList
    },
    selectedItem(){
      console.log(this.pickItem[this.selected])
      return this.pickItem[this.selected]
    }
  }
}
</script>

<style scoped>
  img {
    width: 40%;
    height: inherit;
    aspect-ratio: 1/1;
    padding: 0.5rem;
  }

  tr {
    width: 100%;
    padding: 0.5rem;
    border-bottom: 1px #cccccc solid;
    cursor: pointer;
    text-align: start;
  }

  h5 {
    width: 20%;
    font-size: 1.25rem;
    font-weight: bold;
    text-align: start;
  }

  p {
    width: 80%;
    word-break: break-all;
    font-size: 1rem;
    margin: 0;
    text-align: start;
  }

  #pick-item-container {
    display: flex;
    flex-direction: column;
    border: 2px #cccccc solid;
    width: 80%;
    margin: 3rem;
  }

  #pick-item-header {
    display: flex;
    width: 100%;
  }

  #pick-item-header table {
    width: 100%;
    display: flex;
    flex-direction: column;
    justify-content: flex-start;
    align-items: flex-start;
    border-left: 1px #cccccc solid;
    overflow: auto;
  }

  #pick-item-body {
    display: flex;
    flex-direction: column;
    /* width: 100%; */
    aspect-ratio: 3/1;
    border-top: 1px #cccccc solid;
  }

  .movie-poster {
    aspect-ratio: 1/1.5;
  }

  .pick-item-info {
    display: flex;
    justify-content: stretch;
    align-content: center;
    width: 100%;
    padding: 0.5rem;
  }

  .selected {
    background-color: #cccccc;
    font-weight: bold;
  }
</style>