<template>
  <div id="feed-list">
    <div id="show-btns">
      <h3>보기</h3>
      <button @click="showOption = 'grid'" :class="showOption == 'grid' ? 'g-active':'g' " />
      <button @click="showOption = 'card'" :class="showOption == 'card' ? 'c-active':'c' " />
    </div>
    <div v-if="showOption == 'grid'" id="grid-container">
      <feed-small v-for="feed in feeds"
        :feed="feed"
        :key="feeds.indexOf(feed)" />
    </div>
    <div v-if="showOption == 'card'" id="card-container">
      <feed v-for="feed in feeds"
        :feed="feed"
        :key="feeds.indexOf(feed)" />
    </div>
  </div>
</template>

<script>
import Feed from "@/components/SearchUser/Feed.vue";
import FeedSmall from "@/components/SearchUser/FeedSmall.vue";

export default {
  name: "FeedList",
  data(){
    return {
      showOption: 'grid'
    }
  },
  props: {
    feeds: Array,
  },
  components: {
    Feed,
    FeedSmall
  }
};
</script>

<style scoped>
  h3 {
    margin: 0 1rem;
  }

  button {
    width: 4vh;
    height: 4vh;
    background-size: cover;
    border: none;
    margin: 0.5rem;
    border-radius: 20%;
  }

  #feed-list {
    display: flex;
    flex-direction: column;
    align-items: center;
    width: 100%;
  }

  #show-btns {
    display: flex;
    align-items: center;
    align-self: flex-start;
    box-sizing: content-box;
    margin: 1rem;
  }

  #grid-container {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr 1fr;
    gap: 1rem;
    width: 100%;
    padding: 2rem;
  }

  #card-container {
    display: flex;
    flex-direction: column;
    align-items: center;
  }

  .g {
    background-image: url('../../assets/images/icons/grid.png');
  }

  .g-active {
    background-image: url('../../assets/images/icons/grid-active.png');
  }

  .c {
    background-image: url('../../assets/images/icons/card.png');
  }

  .c-active {
    background-image: url('../../assets/images/icons/card-active.png');
  }
</style>