<template>
  <div :id="`${name}-carousel`">
    <div class="carousel-frame">
      <div :id="`${name}-rail`" class="carousel-rail">
        <img :class="['carousel-items', `${name}-items`]" v-for="idx in nums" 
        :src="items[idx-1].img" :alt="'item no.' + idx" :key="idx">
      </div>
    </div>
    <button @click="paginate(-1)" :id="`${name}-btn-left`" class="left" />
    <button @click="paginate(1)" :id="`${name}-btn-right`" class="right" />
  </div>
</template>

<script>
export default {
  data(){
    return {
      page: 0,
      beforePage: 0,
      nums: null
    }
  },
  props: {
    items: Array,
    name: {
      default: 'default',
      type: String
    },
    w: Number,
    h: Number,
    n: Number
  },
  methods: {
    paginate(payload){
      this.beforePage = this.page
      this.page += payload
    }
  },
  computed: {

  },
  watch: {
    page(){
      if (this.beforePage > this.page){
        const temp = this.items.shift()
        this.items.push(temp)
      }
      else {
        const temp = this.items.pop()
        this.items.unshift(temp)
      }
    }
  },
  mounted(){
    const carousel = document.getElementById(`${this.name}-carousel`)
    const carouselRail = document.getElementById(`${this.name}-rail`)
    const item = document.getElementsByClassName(`${this.name}-items`)
    const btnLeft = document.getElementById(`${this.name}-btn-left`)
    const btnRight = document.getElementById(`${this.name}-btn-right`)
    let width = 800
    let height = 200
    let btnSize = 50
    let nums = 4
    console.log(carouselRail.style)
    carousel.style.cssText = 'box-sizing: content-box; position: relative; max-width: 100%'
    carousel.style.width = '800px'; carousel.style.height = '200px';


    if (this.w){
      width = this.w
      carousel.style.cssText += `width:${width};`
    }
    if (this.h){
      height = this.h
      carousel.style.cssText += `height:${height};`
      btnSize = Math.floor(height / 8)
    }
    if (this.n){
      nums = this.n
    }

    let temp = ''
    for (let i=0; i < nums; i++){
      temp += '1fr '
    }
    carouselRail.style.gridTemplateColumns = temp


    this.nums = nums
    for (let i=0;i<item.length;i++){
      item[i].style.width = `${width/nums}px`
    }
    const horizontal = (btnSize / 2) / width * 100
    const vertical = (btnSize / 2) / height * 100
    btnLeft.style.width = `${btnSize}px`; btnLeft.style.height = `${btnSize}px`
    btnLeft.style.cssText += `left:-${horizontal}%; top:${50-vertical}%;`
    btnRight.style.width = `${btnSize}px`; btnRight.style.height = `${btnSize}px`
    btnRight.style.cssText += `right:-${horizontal}%; top:${50-vertical}%;`
  }
}
</script>

<style scoped>
  button {
    background-size: cover;
    border: none;
    border-radius: 50%;
    opacity: 0.75;
    position: absolute;
  }

  .carousel-frame {
    width: 100%;
    height: 100%;
    position: relative;
    overflow: hidden;
  }

  .carousel-rail {
    width: 100%;
    height: 100%;
    display: grid;
    justify-content: center;
    justify-items: stretch;
    align-items: center;
    gap: 1rem;
  }

  .carousel-items {
    transition: all 0.5s ease;
    display: inline-block;
    width: 100%;
    border-radius: 20px;
    aspect-ratio: 1/1;
    cursor: pointer;
  }

  .left {
    background-image: url('../assets/images/icons/left.png');
  }

  .right {
    background-image: url('../assets/images/icons/right.png');
  }
</style>