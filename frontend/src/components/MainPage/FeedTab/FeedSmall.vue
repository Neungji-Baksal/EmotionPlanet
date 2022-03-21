<template>
  <div class="feed-s" >
    <img class="feed-s-thumbnail" :src="post.postImage" :alt="post.username"
    @mouseover="hover = true">
    <span class="feed-s-info" v-show="hover" @mouseleave="hover = false">
      <span class="info">
        <img src="@/assets/images/icons/heart.png" alt="heart">
        <p>{{ post.likes }}</p>
      </span>
      <span class="info">
        <img src="@/assets/images/icons/chat.png" alt="comment">
        <p>{{ post.comment_cnt }}</p>
      </span>
    </span>
  </div>
</template>

<script>
export default {
  data(){
    return {
      hover: false
    }
  },
  props: {
    post: Object
  },
}
</script>

<style scoped>
  img {
    width: 20px;
    aspect-ratio: 1/1;
  }

  p {
    color: white;
    font-size: 1.125rem;
    margin: 0 0.5rem;
  }

  .feed-s {
    position: relative;
    cursor: pointer;
  }

  .feed-s-thumbnail {
    width: 100%;
    aspect-ratio: 1/1;
    border-radius: 20px;
    position: relative;
  }

  .feed-s-info {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-evenly;
    align-items: center;
    background-color: rgb(0, 0, 0, 0.5);
    position: absolute;
    top: 0;
    left: 0;
    z-index: 1;
    width: 100%;
    height: 100%;
    border-radius: 20px;
    padding: 1rem;
  }

  .info {
    display: flex;
    flex-wrap: nowrap;
    align-items: center;
  }
</style>