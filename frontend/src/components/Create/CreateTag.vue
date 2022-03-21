<template>
  <section id="tag-container">
    <article id="subs">
      <img src="../../assets/images/icons/return.png" alt="" id="back" @click="out">
      <h1>글 쓰기</h1>
    </article>
    <article id="tag-header">
      <h2>활동 태그를 선택해주세요</h2>
      <h3>활동 태그 하나는 필수에요!</h3>
      <h3>알맞는 키워드를 넣어주세요.</h3>
    </article>
    <act-container @check-category="pickTag" @selected="isSelected"/>
    <footer>
      <button id="btn-before" @click="beforePage">이전</button>
      <button id="btn-next" @click="nextPage">다음</button>
    </footer>
  </section>
</template>

<script>
import ActContainer from '@/components/FeedCreate/ActContainer'

export default {
  name: 'Create_tag',
  data: function () {
    return {
      selectedKeyword: '',
      selectedAct: [],
      selectChecked: false,
    }
  },
  components: {
    ActContainer
  },
  methods: {
    out(){
      this.$emit('out')
    },
    beforePage(){
      this.$emit('before-page')
    },
    nextPage(){
      if (!this.selectChecked) {
        // alert('행동 태그를 선택해주세요')
        this.$store.commit('pickYourTagModalActivate')
      } else {
        this.$emit('next-page')
      }
    },
    pickTag (event) {
      // console.log(event)
      this.selectedKeyword = event
    },
    isSelected (event) {
      this.selectChecked = event
    },
    selectAct: function(actKeyword) {
      if (document.getElementById(actKeyword.target.textContent).className === 'checked_category') {
        console.log((actKeyword.target.textContent).className)
        document.getElementById(actKeyword.target.id).className = 'unchecked_category'
      } else {
        document.getElementById(actKeyword.target.id).className = 'checked_category'
      }
      this.selectedKeyword = actKeyword.target.textContent.trim()
      for (let key in this.act_details) {
        if (key === this.selectedKeyword) {
          this.selectedAct = this.act_details[key]
        }
      }
    }
  },

}
</script>

<style scoped>
  h1 {
    font-size: 1.5rem;
    font-weight: bold;
    margin: 0;
  }

  h2 {
    font-size: 2.3rem;
    font-weight: bold;
    margin-bottom: 2rem;
  }

  h3 {
    font-size: 1.4rem;
    margin: 0;
  }
  
  button {
    background-color: #5E39B3;
    color: white;
    font-size: 1.125rem;
    font-weight: bold;
    border: 3px #5E39B3 solid;
    border-radius: 30px;
    padding: 0.2rem 2rem;
    margin: 1rem;
    cursor: pointer;
    line-height: 2rem;
  }

  #tag-container {
    display:flex;
    flex-direction: column;
    justify-content: flex-start;
    align-items: center;
    width: 100%;
    height: 100%;
  }

  #subs {
    display:flex;
    justify-content: center;
    border-bottom: 1px #cccccc solid;
    width: 100%;
    margin-bottom: 2rem;
    padding: 0.5rem;
    position: relative;
  }

  #back {
    width: 25px;
    height: 25px;
    position: absolute;
    left: 2%;
    cursor: pointer;
  }

  #tag-header {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    width: 80%;
    margin-bottom: 2rem;
  }

  footer {
    display:flex;
    justify-content: flex-end;
    width: 80%;
  }

  #btn-before {
    background-color: #777777;
    border: 3px #777777 solid;
  }
</style>